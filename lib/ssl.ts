import tls from 'tls';
import { SSLInfo } from '../types/analysis';

export async function getSslInfo(hostname: string): Promise<SSLInfo> {
  const defaultInfo: SSLInfo = {
    issuer: null,
    subject: null,
    validFrom: null,
    validUntil: null,
    serialNumber: null,
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
          const cert = socket.getPeerCertificate();
          if (!cert || Object.keys(cert).length === 0) {
            socket.end();
            resolve(defaultInfo);
            return;
          }

          const getCertField = (field: string | string[] | undefined) => Array.isArray(field) ? field[0] : field;

          const info: SSLInfo = {
            issuer: getCertField(cert.issuer?.O) || getCertField(cert.issuer?.CN) || null,
            subject: getCertField(cert.subject?.CN) || null,
            validFrom: cert.valid_from || null,
            validUntil: cert.valid_to || null,
            serialNumber: cert.serialNumber || null,
          };
          
          socket.end();
          resolve(info);
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
