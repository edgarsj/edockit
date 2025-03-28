import { X509Certificate } from "@peculiar/x509";
import { count } from "console";

/**
 * Certificate subject information
 */
export interface CertificateSubject {
  country?: string;
  commonName?: string;
  surname?: string;
  givenName?: string;
  serialNumber?: string;
  organization?: string;
}

/**
 * Certificate issuer information
 */
export interface CertificateIssuer {
  country?: string;
  commonName?: string;
  organization?: string;
}

/**
 * Full certificate information
 */
export interface CertificateInfo {
  subject: CertificateSubject;
  validFrom: Date;
  validTo: Date;
  issuer: CertificateIssuer;
  serialNumber?: string;
}

/**
 * Certificate validity check result
 */
export interface CertificateValidityResult {
  isValid: boolean;
  reason?: string;
}

/**
 * Format a certificate string as a proper PEM certificate
 * @param certBase64 Base64-encoded certificate
 * @returns Formatted PEM certificate
 */
export function formatPEM(certBase64?: string): string {
  if (!certBase64) return "";

  // Remove any whitespace from the base64 string
  const cleanBase64 = certBase64.replace(/\s+/g, "");

  // Split the base64 into lines of 64 characters
  const lines = [];
  for (let i = 0; i < cleanBase64.length; i += 64) {
    lines.push(cleanBase64.substring(i, i + 64));
  }

  // Format as PEM certificate
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Extract subject information from an X.509 certificate
 * @param certificate X509Certificate instance
 * @returns Signer information object
 */
export function extractSignerInfo(certificate: X509Certificate): {
  commonName?: string;
  organization?: string;
  country?: string;
  surname?: string;
  givenName?: string;
  serialNumber?: string;
  validFrom: Date;
  validTo: Date;
  issuer: {
    commonName?: string;
    organization?: string;
    country?: string;
  };
} {
  const result: any = {
    validFrom: certificate.notBefore,
    validTo: certificate.notAfter,
    issuer: {},
  };

  // Try to extract fields using various approaches

  // Approach 1: Try direct access to typed subject properties
  try {
    if (
      typeof certificate.subject === "object" &&
      certificate.subject !== null
    ) {
      // Handle subject properties
      const subject = certificate.subject as any;
      result.commonName = subject.commonName;
      result.organization = subject.organizationName;
      result.country = subject.countryName;
    }

    // Handle issuer properties
    if (typeof certificate.issuer === "object" && certificate.issuer !== null) {
      const issuer = certificate.issuer as any;
      result.issuer.commonName = issuer.commonName;
      result.issuer.organization = issuer.organizationName;
      result.issuer.country = issuer.countryName;
    }
  } catch (e) {
    console.warn("Could not extract subject/issuer as objects:", e);
  }

  // Approach 2: Parse subject/issuer as strings if they are strings
  try {
    if (typeof certificate.subject === "string") {
      const subjectStr = certificate.subject as string;

      // Parse the string format (usually CN=name,O=org,C=country)
      const subjectParts = subjectStr.split(",");
      for (const part of subjectParts) {
        const [key, value] = part.trim().split("=");
        if (key === "CN") result.commonName = result.commonName || value;
        if (key === "O") result.organization = result.organization || value;
        if (key === "C") result.country = result.country || value;
        if (key === "SN") result.surname = value;
        if (key === "G" || key === "GN") result.givenName = value;
        if (key === "SERIALNUMBER" || key === "2.5.4.5")
          result.serialNumber = value?.replace("PNOLV-", "");
      }
    }

    if (typeof certificate.issuer === "string") {
      const issuerStr = certificate.issuer as string;

      // Parse the string format
      const issuerParts = issuerStr.split(",");
      for (const part of issuerParts) {
        const [key, value] = part.trim().split("=");
        if (key === "CN")
          result.issuer.commonName = result.issuer.commonName || value;
        if (key === "O")
          result.issuer.organization = result.issuer.organization || value;
        if (key === "C") result.issuer.country = result.issuer.country || value;
      }
    }
  } catch (e) {
    console.warn("Could not extract subject/issuer as strings:", e);
  }

  // Approach 3: Try to use getField method if available
  try {
    if (
      "subjectName" in certificate &&
      (certificate as any).subjectName?.getField
    ) {
      const subjectName = (certificate as any).subjectName;
      // Only set if not already set from previous approaches
      result.commonName = result.commonName || subjectName.getField("CN")?.[0];
      result.surname = result.surname || subjectName.getField("SN")?.[0];
      result.givenName = result.givenName || subjectName.getField("G")?.[0];
      result.serialNumber =
        result.serialNumber ||
        subjectName.getField("2.5.4.5")?.[0]?.replace("PNOLV-", "");
      result.country = result.country || subjectName.getField("C")?.[0];
      result.organization =
        result.organization || subjectName.getField("O")?.[0];
    }
  } catch (e) {
    console.warn("Could not extract fields using getField method:", e);
  }

  // Get the serial number from the certificate if not found in subject
  if (!result.serialNumber && certificate.serialNumber) {
    result.serialNumber = certificate.serialNumber;
  }

  return result;
}

/**
 * Parse a certificate from base64 data
 * @param certData Base64-encoded certificate data
 * @returns Parsed certificate information
 */
export async function parseCertificate(
  certData: string,
): Promise<CertificateInfo> {
  try {
    let pemCert = certData;

    // Check if it's already in PEM format, if not, convert it
    if (!certData.includes("-----BEGIN CERTIFICATE-----")) {
      // Only clean non-PEM format data before conversion
      const cleanedCertData = certData.replace(/[\r\n\s]/g, "");
      pemCert = formatPEM(cleanedCertData);
    }
    const cert = new X509Certificate(pemCert);
    const signerInfo = extractSignerInfo(cert);

    return {
      subject: {
        commonName: signerInfo.commonName,
        organization: signerInfo.organization,
        country: signerInfo.country,
        surname: signerInfo.surname,
        givenName: signerInfo.givenName,
        serialNumber: signerInfo.serialNumber,
      },
      validFrom: signerInfo.validFrom,
      validTo: signerInfo.validTo,
      issuer: signerInfo.issuer,
      serialNumber: cert.serialNumber,
    };
  } catch (error) {
    console.error("Certificate parsing error:", error);
    throw new Error(
      "Failed to parse certificate: " +
        (error instanceof Error ? error.message : String(error)),
    );
  }
}

/**
 * Check if a certificate was valid at a specific time
 * @param cert Certificate object or info
 * @param checkTime The time to check validity against (defaults to current time)
 * @returns Validity check result
 */
export function checkCertificateValidity(
  cert: X509Certificate | CertificateInfo,
  checkTime: Date = new Date(),
): CertificateValidityResult {
  // Extract validity dates based on input type
  const validFrom = "notBefore" in cert ? cert.notBefore : cert.validFrom;
  const validTo = "notAfter" in cert ? cert.notAfter : cert.validTo;

  // Check if certificate is valid at the specified time
  if (checkTime < validFrom) {
    return {
      isValid: false,
      reason: `Certificate not yet valid. Valid from ${validFrom.toISOString()}`,
    };
  }

  if (checkTime > validTo) {
    return {
      isValid: false,
      reason: `Certificate expired. Valid until ${validTo.toISOString()}`,
    };
  }

  return { isValid: true };
}

/**
 * Extract the public key information from a certificate
 * @param cert The X.509 certificate
 * @returns Public key information
 */
export function getPublicKeyInfo(cert: X509Certificate): {
  algorithm: string;
  namedCurve?: string;
  rawData: ArrayBuffer;
} {
  const algorithm = cert.publicKey.algorithm;

  return {
    algorithm: algorithm.name,
    ...("namedCurve" in algorithm
      ? {
          namedCurve: (algorithm as any).namedCurve as string,
        }
      : {}),
    rawData: cert.publicKey.rawData,
  };
}

/**
 * Helper function to get signer display name from certificate
 * @param certInfo Certificate information
 * @returns Formatted display name
 */
export function getSignerDisplayName(certInfo: CertificateInfo): string {
  const { subject } = certInfo;

  if (subject.givenName && subject.surname) {
    return `${subject.givenName} ${subject.surname}`;
  }

  if (subject.commonName) {
    return subject.commonName;
  }

  // Fallback to serial number if available
  return subject.serialNumber || "Unknown Signer";
}

/**
 * Helper function to format certificate validity period in a human-readable format
 * @param certInfo Certificate information
 * @returns Formatted validity period
 */
export function formatValidityPeriod(certInfo: CertificateInfo): string {
  const { validFrom, validTo } = certInfo;

  const formatDate = (date: Date) => {
    return date.toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  };

  return `${formatDate(validFrom)} to ${formatDate(validTo)}`;
}
