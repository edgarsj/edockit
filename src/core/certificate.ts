import { X509Certificate } from '@peculiar/x509';

export interface CertificateInfo {
  subject: {
    commonName?: string;
    organization?: string;
    country?: string;
    [key: string]: string | undefined;
  };
  issuer: {
    commonName?: string;
    organization?: string;
    country?: string;
    [key: string]: string | undefined;
  };
  validFrom: Date;
  validTo: Date;
  serialNumber: string;
}

/**
 * Parse certificate data from base64-encoded string
 * @param certificateBase64 Base64-encoded certificate data
 * @returns Parsed certificate information
 */
export function parseCertificate(certificateBase64: string): CertificateInfo {
  try {
    // Remove whitespace and newlines from base64 string
    const cleanBase64 = certificateBase64.replace(/\s+/g, '');
    
    // Parse the certificate
    const cert = new X509Certificate(cleanBase64);
    
    // Extract subject info
    const subject: Record<string, string> = {};
    for (const [key, value] of Object.entries(cert.subject)) {
      if (typeof value === 'string') {
        subject[key] = value;
      }
    }
    
    // Extract issuer info
    const issuer: Record<string, string> = {};
    for (const [key, value] of Object.entries(cert.issuer)) {
      if (typeof value === 'string') {
        issuer[key] = value;
      }
    }
    
    return {
      subject: {
        commonName: subject.commonName,
        organization: subject.organizationName,
        country: subject.countryName,
        ...subject
      },
      issuer: {
        commonName: issuer.commonName,
        organization: issuer.organizationName,
        country: issuer.countryName,
        ...issuer
      },
      validFrom: cert.notBefore,
      validTo: cert.notAfter,
      serialNumber: cert.serialNumber
    };
  } catch (error) {
    throw new Error(`Failed to parse certificate: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Validate if a certificate was valid at a specific time
 * @param certificateInfo Certificate information
 * @param time The time to check validity for (defaults to current time)
 * @returns Whether the certificate was valid at the specified time
 */
export function isCertificateValidAtTime(
  certificateInfo: CertificateInfo,
  time: Date = new Date()
): boolean {
  return time >= certificateInfo.validFrom && time <= certificateInfo.validTo;
}
