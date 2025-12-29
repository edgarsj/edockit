// src/core/revocation/ocsp.ts

import { X509Certificate, AuthorityInfoAccessExtension } from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import {
  OCSPRequest,
  OCSPResponse,
  TBSRequest,
  Request,
  CertID,
  OCSPResponseStatus,
  BasicOCSPResponse,
} from "@peculiar/asn1-ocsp";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { OctetString } from "@peculiar/asn1-schema";
import { RevocationResult } from "./types";
import { fetchOCSP, fetchIssuerCertificate } from "./fetch";
import { arrayBufferToBase64, arrayBufferToPEM, hexToArrayBuffer } from "../../utils/encoding";

/**
 * OID for Authority Information Access extension
 */
const id_pe_authorityInfoAccess = "1.3.6.1.5.5.7.1.1";

/**
 * SHA-1 algorithm identifier for OCSP
 */
const SHA1_OID = "1.3.14.3.2.26";

/**
 * Compute SHA-1 hash of data (cross-platform)
 */
async function computeSHA1(data: ArrayBuffer): Promise<ArrayBuffer> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    return crypto.subtle.digest("SHA-1", data);
  }
  // Node.js fallback
  const nodeCrypto = require("crypto");
  const hash = nodeCrypto.createHash("sha1");
  hash.update(Buffer.from(data));
  return hash.digest().buffer;
}

/**
 * Extract OCSP responder URLs from certificate
 * @param cert X509Certificate to extract OCSP URLs from
 * @returns Array of OCSP responder URLs
 */
export function extractOCSPUrls(cert: X509Certificate): string[] {
  try {
    const aiaExt = cert.getExtension(
      id_pe_authorityInfoAccess,
    ) as AuthorityInfoAccessExtension | null;
    if (!aiaExt) {
      return [];
    }

    // Get OCSP URLs from the extension
    return aiaExt.ocsp.filter((gn) => gn.type === "url").map((gn) => gn.value);
  } catch {
    return [];
  }
}

/**
 * Extract CA Issuers URLs from certificate (for fetching issuer cert)
 * @param cert X509Certificate to extract URLs from
 * @returns Array of CA Issuers URLs
 */
export function extractCAIssuersUrls(cert: X509Certificate): string[] {
  try {
    const aiaExt = cert.getExtension(
      id_pe_authorityInfoAccess,
    ) as AuthorityInfoAccessExtension | null;
    if (!aiaExt) {
      return [];
    }

    return aiaExt.caIssuers.filter((gn) => gn.type === "url").map((gn) => gn.value);
  } catch {
    return [];
  }
}

/**
 * Find issuer certificate from certificate chain
 * @param cert Certificate to find issuer for
 * @param chain Array of PEM-formatted certificates
 * @returns Issuer certificate or null if not found
 */
export function findIssuerInChain(cert: X509Certificate, chain: string[]): X509Certificate | null {
  const issuerName = cert.issuer;

  for (const pemCert of chain) {
    try {
      const chainCert = new X509Certificate(pemCert);
      // Check if this cert's subject matches our cert's issuer
      if (chainCert.subject === issuerName) {
        return chainCert;
      }
    } catch {
      // Skip invalid certificates
    }
  }

  return null;
}

/**
 * Fetch issuer certificate from AIA extension
 * @param cert Certificate to fetch issuer for
 * @param timeout Timeout in ms
 * @param proxyUrl Optional CORS proxy URL
 * @returns Issuer certificate or null
 */
export async function fetchIssuerFromAIA(
  cert: X509Certificate,
  timeout: number = 5000,
  proxyUrl?: string,
): Promise<X509Certificate | null> {
  const urls = extractCAIssuersUrls(cert);

  for (const url of urls) {
    try {
      const result = await fetchIssuerCertificate(url, timeout, proxyUrl);
      if (result.ok && result.data) {
        // Try to parse as DER first, then PEM
        try {
          return new X509Certificate(result.data);
        } catch {
          // Try converting to PEM
          const pem = arrayBufferToPEM(result.data);
          return new X509Certificate(pem);
        }
      }
    } catch {
      // Try next URL
    }
  }

  return null;
}

/**
 * Build OCSP request for a certificate
 * @param cert Certificate to check
 * @param issuerCert Issuer certificate
 * @returns DER-encoded OCSP request
 */
export async function buildOCSPRequest(
  cert: X509Certificate,
  issuerCert: X509Certificate,
): Promise<ArrayBuffer> {
  // Get issuer name hash (SHA-1 of issuer's DN in DER)
  const issuerNameDer = AsnConvert.serialize(issuerCert.subjectName.toJSON());
  const issuerNameHash = await computeSHA1(issuerNameDer);

  // Get issuer key hash (SHA-1 of issuer's public key)
  const issuerKeyHash = await computeSHA1(issuerCert.publicKey.rawData);

  // Get certificate serial number
  const serialNumber = hexToArrayBuffer(cert.serialNumber);

  // Build CertID
  const certId = new CertID({
    hashAlgorithm: new AlgorithmIdentifier({ algorithm: SHA1_OID }),
    issuerNameHash: new OctetString(issuerNameHash),
    issuerKeyHash: new OctetString(issuerKeyHash),
    serialNumber: serialNumber,
  });

  // Build request
  const request = new Request({ reqCert: certId });

  // Build TBS request
  const tbsRequest = new TBSRequest({
    requestList: [request],
  });

  // Build OCSP request
  const ocspRequest = new OCSPRequest({ tbsRequest });

  return AsnConvert.serialize(ocspRequest);
}

/**
 * Parse OCSP response and extract revocation status
 * @param responseData DER-encoded OCSP response
 * @returns Revocation result
 */
export function parseOCSPResponse(responseData: ArrayBuffer): RevocationResult {
  const now = new Date();

  try {
    const response = AsnConvert.parse(responseData, OCSPResponse);

    // Check response status
    switch (response.responseStatus) {
      case OCSPResponseStatus.successful:
        break;
      case OCSPResponseStatus.malformedRequest:
        return {
          isValid: false,
          status: "error",
          method: "ocsp",
          reason: "OCSP responder returned: malformed request",
          checkedAt: now,
        };
      case OCSPResponseStatus.internalError:
        return {
          isValid: false,
          status: "error",
          method: "ocsp",
          reason: "OCSP responder returned: internal error",
          checkedAt: now,
        };
      case OCSPResponseStatus.tryLater:
        return {
          isValid: false,
          status: "unknown",
          method: "ocsp",
          reason: "OCSP responder returned: try later",
          checkedAt: now,
        };
      case OCSPResponseStatus.sigRequired:
        return {
          isValid: false,
          status: "error",
          method: "ocsp",
          reason: "OCSP responder requires signature",
          checkedAt: now,
        };
      case OCSPResponseStatus.unauthorized:
        return {
          isValid: false,
          status: "error",
          method: "ocsp",
          reason: "OCSP responder returned: unauthorized",
          checkedAt: now,
        };
      default:
        return {
          isValid: false,
          status: "error",
          method: "ocsp",
          reason: `OCSP responder returned unknown status: ${response.responseStatus}`,
          checkedAt: now,
        };
    }

    // Parse response bytes
    if (!response.responseBytes) {
      return {
        isValid: false,
        status: "error",
        method: "ocsp",
        reason: "OCSP response has no response bytes",
        checkedAt: now,
      };
    }

    // Parse BasicOCSPResponse
    const basicResponse = AsnConvert.parse(
      response.responseBytes.response.buffer,
      BasicOCSPResponse,
    );

    // Get the first single response
    const responses = basicResponse.tbsResponseData.responses;
    if (!responses || responses.length === 0) {
      return {
        isValid: false,
        status: "error",
        method: "ocsp",
        reason: "OCSP response contains no certificate status",
        checkedAt: now,
      };
    }

    const singleResponse = responses[0];
    const certStatus = singleResponse.certStatus;

    // Check certificate status
    if (certStatus.good !== undefined) {
      return {
        isValid: true,
        status: "good",
        method: "ocsp",
        checkedAt: now,
      };
    } else if (certStatus.revoked) {
      return {
        isValid: false,
        status: "revoked",
        method: "ocsp",
        reason:
          certStatus.revoked.revocationReason !== undefined
            ? `Certificate revoked (reason: ${certStatus.revoked.revocationReason})`
            : "Certificate revoked",
        revokedAt: certStatus.revoked.revocationTime,
        checkedAt: now,
      };
    } else if (certStatus.unknown !== undefined) {
      return {
        isValid: false,
        status: "unknown",
        method: "ocsp",
        reason: "OCSP responder does not know about this certificate",
        checkedAt: now,
      };
    }

    return {
      isValid: false,
      status: "error",
      method: "ocsp",
      reason: "Unexpected certificate status in OCSP response",
      checkedAt: now,
    };
  } catch (error) {
    return {
      isValid: false,
      status: "error",
      method: "ocsp",
      reason: `Failed to parse OCSP response: ${error instanceof Error ? error.message : String(error)}`,
      checkedAt: now,
    };
  }
}

/**
 * Check certificate revocation via OCSP
 * @param cert Certificate to check
 * @param issuerCert Issuer certificate (optional, will try to find/fetch)
 * @param options OCSP check options
 * @returns Revocation result
 */
export async function checkOCSP(
  cert: X509Certificate,
  issuerCert: X509Certificate | null,
  options: { timeout?: number; certificateChain?: string[]; proxyUrl?: string } = {},
): Promise<RevocationResult> {
  const { timeout = 5000, certificateChain = [], proxyUrl } = options;
  const now = new Date();

  // Get OCSP URLs
  const ocspUrls = extractOCSPUrls(cert);
  if (ocspUrls.length === 0) {
    return {
      isValid: false,
      status: "unknown",
      method: "ocsp",
      reason: "Certificate has no OCSP responder URL",
      checkedAt: now,
    };
  }

  // Try to find issuer certificate
  let issuer = issuerCert;
  if (!issuer) {
    // Try certificate chain first
    issuer = findIssuerInChain(cert, certificateChain);
  }
  if (!issuer) {
    // Try AIA extension
    issuer = await fetchIssuerFromAIA(cert, timeout, proxyUrl);
  }
  if (!issuer) {
    return {
      isValid: false,
      status: "unknown",
      method: "ocsp",
      reason: "Could not find or fetch issuer certificate for OCSP",
      checkedAt: now,
    };
  }

  // Build OCSP request
  let request: ArrayBuffer;
  try {
    request = await buildOCSPRequest(cert, issuer);
  } catch (error) {
    return {
      isValid: false,
      status: "error",
      method: "ocsp",
      reason: `Failed to build OCSP request: ${error instanceof Error ? error.message : String(error)}`,
      checkedAt: now,
    };
  }

  // Try each OCSP URL
  for (const url of ocspUrls) {
    try {
      const result = await fetchOCSP(url, request, timeout, proxyUrl);
      if (result.ok && result.data) {
        return parseOCSPResponse(result.data);
      }
    } catch {
      // Try next URL
    }
  }

  return {
    isValid: false,
    status: "error",
    method: "ocsp",
    reason: "All OCSP requests failed",
    checkedAt: now,
  };
}
