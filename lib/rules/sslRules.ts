import { SecurityRule } from '../../types/rules';
import { SSLInfo } from '../../types/analysis';

/**
 * Evaluates the extracted SSL intelligence to generate individual security rules.
 * Each rule evaluates a discrete SSL component (Protocol, Cipher, Validity, SANs).
 * 
 * @param urlObj - The parsed URL object.
 * @param ssl - The detailed SSL intelligence object.
 * @returns An array of generated SecurityRules.
 */
export function evaluateSslRules(urlObj: URL, ssl: SSLInfo): SecurityRule[] {
  const rules: SecurityRule[] = [];

  // Skip SSL evaluation if not HTTPS
  if (urlObj.protocol !== 'https:') {
    return rules;
  }

  // 1. Missing SSL or Handshake Failure
  if (!ssl.issuer || !ssl.validFrom) {
    rules.push({
      id: 'INVALID_SSL',
      title: 'Invalid SSL Certificate',
      description: 'The server failed to provide a valid SSL certificate during the handshake.',
      recommendation: 'Ensure the server is correctly configured to serve an SSL certificate and is not blocking requests.',
      category: 'SSL',
      severity: 'Critical',
      weight: 30,
      triggered: true
    });
    // Stop further analysis if there is no cert
    return rules;
  }

  // 2. Protocol Version Checks
  if (ssl.tlsVersion) {
    const isWeakTls = ssl.tlsVersion === 'TLSv1' || ssl.tlsVersion === 'TLSv1.1';
    rules.push({
      id: 'WEAK_TLS_VERSION',
      title: 'Deprecated TLS Version',
      description: `The server negotiated an outdated and insecure protocol: ${ssl.tlsVersion}.`,
      recommendation: 'Upgrade the server configuration to disable TLS 1.0 and TLS 1.1 and enforce TLS 1.2 or TLS 1.3.',
      category: 'SSL',
      severity: isWeakTls ? 'High' : 'Info',
      weight: isWeakTls ? 20 : 0,
      triggered: isWeakTls
    });

    const isModernTls = ssl.tlsVersion === 'TLSv1.3';
    rules.push({
      id: 'MODERN_TLS_VERSION',
      title: 'Modern TLS Version',
      description: `The server negotiated a highly secure protocol: ${ssl.tlsVersion}.`,
      category: 'SSL',
      severity: 'Info',
      weight: 0,
      triggered: isModernTls
    });
  }

  // 3. Cipher Suite Checks
  if (ssl.cipherName) {
    const cipherUpper = ssl.cipherName.toUpperCase();
    const isWeakCipher = cipherUpper.includes('RC4') || cipherUpper.includes('DES') || cipherUpper.includes('MD5');
    rules.push({
      id: 'WEAK_CIPHER',
      title: 'Weak Cipher Suite Negotiated',
      description: `The server negotiated a weak or obsolete cipher: ${ssl.cipherName}.`,
      recommendation: 'Update the server cipher suite list to remove RC4, DES, and MD5 algorithms. Prioritize AES-GCM or ChaCha20.',
      category: 'SSL',
      severity: 'High',
      weight: 20,
      triggered: isWeakCipher
    });
  }

  // 4. Certificate Validity (Not yet valid)
  if (ssl.isValid === false && ssl.isExpired === false) {
    rules.push({
      id: 'CERT_NOT_YET_VALID',
      title: 'Certificate Not Yet Valid',
      description: 'The certificate validFrom date is in the future. It is not yet active.',
      recommendation: 'Check the server system clock for accuracy, or wait until the certificate becomes active.',
      category: 'SSL',
      severity: 'High',
      weight: 30,
      triggered: true
    });
  }

  // 5. Certificate Expiry Checks
  if (ssl.isExpired) {
    rules.push({
      id: 'EXPIRED_CERTIFICATE',
      title: 'Expired Certificate',
      description: 'The SSL certificate has expired.',
      recommendation: 'Renew the SSL certificate immediately to restore secure connections.',
      category: 'SSL',
      severity: 'Critical',
      weight: 40,
      triggered: true
    });
  } else if (typeof ssl.daysRemaining === 'number') {
    const soon = ssl.daysRemaining <= 7;
    const moderatelySoon = ssl.daysRemaining > 7 && ssl.daysRemaining <= 30;
    
    rules.push({
      id: 'CERT_EXPIRES_SOON',
      title: 'Certificate Expires Soon',
      description: `The certificate will expire in ${ssl.daysRemaining} days.`,
      recommendation: 'Schedule a renewal of the SSL certificate before it expires to prevent downtime.',
      category: 'SSL',
      severity: soon ? 'High' : 'Medium',
      weight: soon ? 15 : 10,
      triggered: soon || moderatelySoon
    });

    const healthy = ssl.daysRemaining > 30;
    rules.push({
      id: 'CERT_HEALTHY_EXPIRY',
      title: 'Healthy Certificate Expiry',
      description: `The certificate is valid for another ${ssl.daysRemaining} days.`,
      category: 'SSL',
      severity: 'Info',
      weight: 0,
      triggered: healthy
    });
  }

  // 6. Self-Signed Detection
  if (ssl.isSelfSigned) {
    rules.push({
      id: 'SELF_SIGNED_CERTIFICATE',
      title: 'Self-Signed Certificate',
      description: 'The certificate was signed by itself rather than a trusted Certificate Authority (CA).',
      recommendation: 'Obtain an SSL certificate from a recognized Certificate Authority (like Let\'s Encrypt, DigiCert).',
      category: 'SSL',
      severity: 'High',
      weight: 30,
      triggered: true
    });
  }

  // 7. Subject Alternative Names (SAN) Check
  const hasSan = ssl.subjectAltNames && ssl.subjectAltNames.length > 0;
  rules.push({
    id: 'NO_SAN',
    title: 'Missing Subject Alternative Names',
    description: 'The certificate lacks Subject Alternative Name (SAN) entries, which are required by modern browsers.',
    recommendation: 'Reissue the certificate ensuring the domain names are listed in the SAN extension.',
    category: 'SSL',
    severity: 'Medium',
    weight: 15,
    triggered: !hasSan
  });

  // 8. Key Strength Check
  if (ssl.pubKeyAlgorithm === 'RSA' && ssl.keySize && ssl.keySize < 2048) {
    rules.push({
      id: 'WEAK_RSA_KEY',
      title: 'Weak RSA Key Size',
      description: `The certificate uses a weak RSA key size (${ssl.keySize} bits).`,
      recommendation: 'Generate a new CSR with an RSA key size of at least 2048 bits (or use ECDSA).',
      category: 'SSL',
      severity: 'Medium',
      weight: 15,
      triggered: true
    });
  }

  return rules;
}
