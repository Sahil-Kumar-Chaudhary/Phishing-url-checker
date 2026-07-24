import tls from 'tls';
import { SSLInfo } from '../types/analysis';

/**
 * Initiates a TLS connection to retrieve the deep SSL certificate intelligence.
 * Extracts TLS protocol, cipher, certificate chain lengths, SANs, and key material
 * using Node's standard `tls` module. 
 * 
 * Note on Certificate Chains: Node's TLS does not natively expose the full verified root 
 * chain if the root CA isn't explicitly sent by the server or isn't part of Node's 
 * internal CA trust store. As requested, we rely strictly on what Node exposes 
 * without custom workarounds.
 * 
 * @param hostname - The domain name to inspect.
 * @returns A promise resolving to the parsed SSL intelligence details.
 */
export async function getSslInfo(hostname: string): Promise<SSLInfo> {
  const defaultInfo: SSLInfo = {
    issuer: null,
    subject: null,
    validFrom: null,
    validUntil: null,
    serialNumber: null,
    tlsVersion: null,
    cipherName: null,
    cipherVersion: null,
    daysRemaining: null,
    isSelfSigned: null,
    subjectAltNames: null,
    chainAvailable: null,
    chainLength: null,
    pubKeyAlgorithm: null,
    signatureAlgorithm: null,
    keySize: null,
    isValid: null,
    isExpired: null,
  };

  return new Promise((resolve) => {
    try {
      const socket = tls.connect(
        {
          host: hostname,
          port: 443,
          servername: hostname, // SNI
          rejectUnauthorized: false, // We want the cert even if invalid to analyze it
        },
        () => {
          try {
            // Retrieve detailed peer certificate to get the issuer certificate chain
            const cert = socket.getPeerCertificate(true);
            if (!cert || Object.keys(cert).length === 0) {
              socket.end();
              resolve(defaultInfo);
              return;
            }

            const getCertField = (field: string | string[] | undefined) => Array.isArray(field) ? field[0] : field;
            
            const issuer = getCertField(cert.issuer?.O) || getCertField(cert.issuer?.CN) || null;
            const subject = getCertField(cert.subject?.O) || getCertField(cert.subject?.CN) || null;
            
            const validFrom = cert.valid_from || null;
            const validUntil = cert.valid_to || null;
            
            // Calculate Validity and Expiry
            let daysRemaining: number | null = null;
            let isExpired: boolean | null = null;
            let isValid: boolean | null = null;
            const now = Date.now();

            if (validFrom && validUntil) {
              const fromTime = new Date(validFrom).getTime();
              const untilTime = new Date(validUntil).getTime();
              
              isExpired = now > untilTime;
              isValid = now >= fromTime && now <= untilTime;
              
              if (!isExpired) {
                daysRemaining = Math.floor((untilTime - now) / (1000 * 60 * 60 * 24));
              } else {
                daysRemaining = 0;
              }
            }

            // Self-Signed Detection: If Issuer and Subject match precisely
            const isSelfSigned = !!(issuer && subject && issuer === subject);

            // SANs Parsing (Node returns SANs as a comma-separated string like 'DNS:example.com, IP Address:1.2.3.4')
            let subjectAltNames: string[] | null = null;
            if (cert.subjectaltname) {
              subjectAltNames = cert.subjectaltname.split(',').map(s => s.trim().replace(/^DNS:/, '').replace(/^IP Address:/, ''));
            }

            // Calculate Chain Length natively using Node's issuerCertificate traversal
            let chainLength = 1;
            let currentCert = cert;
            while (currentCert.issuerCertificate && currentCert.fingerprint !== currentCert.issuerCertificate.fingerprint) {
              chainLength++;
              currentCert = currentCert.issuerCertificate;
            }

            // Extract Protocol and Cipher
            const protocol = socket.getProtocol();
            const cipher = socket.getCipher();

            // Extract Algorithm Details
            let pubKeyAlgorithm: string | null = null;
            if (cert.asn1Curve || cert.nistCurve) {
              pubKeyAlgorithm = 'ECDSA';
            } else if (cert.modulus && cert.exponent) {
              pubKeyAlgorithm = 'RSA';
            }

            const info: SSLInfo = {
              issuer,
              subject: getCertField(cert.subject?.CN) || null, // Keeping backward compatibility for subject CN
              validFrom,
              validUntil,
              serialNumber: cert.serialNumber || null,
              tlsVersion: protocol || null,
              cipherName: cipher?.name || null,
              cipherVersion: cipher?.version || null,
              daysRemaining,
              isSelfSigned,
              subjectAltNames,
              chainAvailable: chainLength > 1,
              chainLength,
              pubKeyAlgorithm,
              signatureAlgorithm: null, // PeerCertificate in Node types typically lacks direct signature algorithm exposure without raw parsing
              keySize: cert.bits || null,
              isValid,
              isExpired,
            };
            
            socket.end();
            resolve(info);
          } catch (e) {
            socket.end();
            resolve(defaultInfo);
          }
        }
      );

      socket.on('error', () => {
        resolve(defaultInfo);
      });

      socket.setTimeout(5000, () => {
        socket.destroy();
        resolve(defaultInfo);
      });

    } catch (error) {
      resolve(defaultInfo);
    }
  });
}
