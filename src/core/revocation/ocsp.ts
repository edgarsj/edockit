// src/core/revocation/ocsp.ts

import {
  X509Certificate,
  AuthorityInfoAccessExtension,
  ExtendedKeyUsageExtension,
  AlgorithmProvider,
  Name,
  PublicKey,
} from "@peculiar/x509";
import { AsnConvert, AsnParser } from "@peculiar/asn1-schema";
import {
  OCSPRequest,
  OCSPResponse,
  TBSRequest,
  Request,
  CertID,
  OCSPResponseStatus,
  BasicOCSPResponse,
  ResponderID,
  SingleResponse,
} from "@peculiar/asn1-ocsp";
import { AlgorithmIdentifier, Certificate } from "@peculiar/asn1-x509";
import { OctetString } from "@peculiar/asn1-schema";
import { RevocationResult, MAX_URLS_PER_CERTIFICATE, REVOCATION_CLOCK_SKEW_MS } from "./types";
import { fetchOCSP, fetchIssuerCertificate, DEFAULT_MAX_OCSP_BYTES } from "./fetch";
import {
  arrayBufferToHex,
  arrayBufferToPEM,
  base64ToArrayBuffer,
  hexToArrayBuffer,
} from "../../utils/encoding";

/**
 * OID for Authority Information Access extension
 */
const id_pe_authorityInfoAccess = "1.3.6.1.5.5.7.1.1";

/**
 * OID for Extended Key Usage extension
 */
const id_ce_extKeyUsage = "2.5.29.37";

/**
 * id-kp-OCSPSigning extended key usage
 */
const id_kp_OCSPSigning = "1.3.6.1.5.5.7.3.9";

/**
 * id-pkix-ocsp-basic response type
 */
const id_pkix_ocsp_basic = "1.3.6.1.5.5.7.48.1.1";

/**
 * SHA-1 algorithm identifier for OCSP
 */
const SHA1_OID = "1.3.14.3.2.26";

/**
 * Hash algorithms accepted in a response CertID
 */
const CERT_ID_HASH_ALGORITHMS: Record<string, string> = {
  [SHA1_OID]: "SHA-1",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
};

/**
 * Maximum age of an OCSP response that carries no nextUpdate
 */
const OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_MS = 24 * 60 * 60 * 1000;

/**
 * Coordinate size in bytes per named curve (for ECDSA signature conversion)
 */
const EC_COORDINATE_SIZE: Record<string, number> = {
  "P-256": 32,
  "P-384": 48,
  "P-521": 66,
};

/**
 * Compute a digest (cross-platform)
 */
async function computeDigest(algorithm: string, data: BufferSource): Promise<ArrayBuffer> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    return crypto.subtle.digest(algorithm, data);
  }
  // Node.js fallback
  const nodeCrypto = require("crypto");
  const hash = nodeCrypto.createHash(algorithm.replace("-", "").toLowerCase());
  hash.update(Buffer.from(data as ArrayBuffer));
  const digest: Buffer = hash.digest();
  return new Uint8Array(digest).buffer;
}

/**
 * Compute SHA-1 hash of data (cross-platform)
 */
async function computeSHA1(data: ArrayBuffer): Promise<ArrayBuffer> {
  return computeDigest("SHA-1", data);
}

function getSubtle(): SubtleCrypto {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    return crypto.subtle;
  }
  // Node.js fallback
  return require("crypto").webcrypto.subtle;
}

function bytesEqual(a: BufferSource, b: BufferSource): boolean {
  const x = toUint8(a);
  const y = toUint8(b);
  if (x.byteLength !== y.byteLength) return false;
  for (let i = 0; i < x.byteLength; i++) {
    if (x[i] !== y[i]) return false;
  }
  return true;
}

function toUint8(data: BufferSource): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

function normalizeSerial(hex: string): string {
  return hex.toLowerCase().replace(/^0+(?=.)/, "") || "0";
}

/**
 * Convert a DER-encoded ECDSA signature (SEQUENCE { r INTEGER, s INTEGER }) to
 * the fixed-size r||s form WebCrypto expects.
 */
export function ecdsaDerToRaw(der: Uint8Array, coordinateSize: number): Uint8Array | null {
  let offset = 0;
  const readLength = (): number | null => {
    if (offset >= der.length) return null;
    let length = der[offset++];
    if (length & 0x80) {
      const count = length & 0x7f;
      if (count === 0 || count > 2 || offset + count > der.length) return null;
      length = 0;
      for (let i = 0; i < count; i++) {
        length = (length << 8) | der[offset++];
      }
    }
    return length;
  };
  const readInteger = (): Uint8Array | null => {
    if (der[offset++] !== 0x02) return null;
    const length = readLength();
    if (length === null || offset + length > der.length) return null;
    let value = der.subarray(offset, offset + length);
    offset += length;
    while (value.length > 1 && value[0] === 0) {
      value = value.subarray(1);
    }
    if (value.length > coordinateSize) return null;
    const padded = new Uint8Array(coordinateSize);
    padded.set(value, coordinateSize - value.length);
    return padded;
  };

  if (der[offset++] !== 0x30) return null;
  const seqLength = readLength();
  if (seqLength === null || offset + seqLength !== der.length) return null;
  const r = readInteger();
  const s = readInteger();
  if (!r || !s || offset !== der.length) return null;
  const raw = new Uint8Array(coordinateSize * 2);
  raw.set(r, 0);
  raw.set(s, coordinateSize);
  return raw;
}

/**
 * Verify a signature over data using a public key and an ASN.1 signature
 * algorithm identifier. Supports RSASSA-PKCS1-v1_5, RSA-PSS and ECDSA.
 * Returns false for unsupported algorithms or key/algorithm mismatches.
 */
export async function verifyAsnSignature(
  publicKey: PublicKey,
  signatureAlgorithm: AlgorithmIdentifier,
  signature: BufferSource,
  data: BufferSource,
): Promise<boolean> {
  try {
    const webAlgorithm = new AlgorithmProvider().toWebAlgorithm(signatureAlgorithm) as Algorithm & {
      hash?: unknown;
    };
    if (
      !webAlgorithm ||
      !["RSASSA-PKCS1-v1_5", "RSA-PSS", "ECDSA"].includes(webAlgorithm.name) ||
      !webAlgorithm.hash
    ) {
      return false;
    }

    const keyAlgorithm = { ...publicKey.algorithm, ...webAlgorithm } as Algorithm & {
      namedCurve?: string;
    };
    // An EC key can only verify ECDSA signatures and an RSA key only RSA ones.
    if ((publicKey.algorithm.name === "ECDSA") !== (webAlgorithm.name === "ECDSA")) {
      return false;
    }

    const key = await publicKey.export(keyAlgorithm, ["verify"]);

    let signatureBytes: Uint8Array = toUint8(signature);
    if (keyAlgorithm.name === "ECDSA") {
      const size = EC_COORDINATE_SIZE[keyAlgorithm.namedCurve ?? ""];
      if (!size) return false;
      const raw = ecdsaDerToRaw(signatureBytes, size);
      if (!raw) return false;
      signatureBytes = raw;
    }

    return await getSubtle().verify(keyAlgorithm, key, new Uint8Array(signatureBytes), data);
  } catch {
    return false;
  }
}

/**
 * Extract OCSP responder URLs from certificate
 * @param cert X509Certificate to extract OCSP URLs from
 * @returns Array of OCSP responder URLs (http and https only)
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
    return aiaExt.ocsp
      .filter((gn) => gn.type === "url")
      .map((gn) => gn.value)
      .filter(isHttpUrl);
  } catch {
    return [];
  }
}

/**
 * Extract CA Issuers URLs from certificate (for fetching issuer cert)
 * @param cert X509Certificate to extract URLs from
 * @returns Array of CA Issuers URLs (http and https only)
 */
export function extractCAIssuersUrls(cert: X509Certificate): string[] {
  try {
    const aiaExt = cert.getExtension(
      id_pe_authorityInfoAccess,
    ) as AuthorityInfoAccessExtension | null;
    if (!aiaExt) {
      return [];
    }

    return aiaExt.caIssuers
      .filter((gn) => gn.type === "url")
      .map((gn) => gn.value)
      .filter(isHttpUrl);
  } catch {
    return [];
  }
}

function isHttpUrl(url: string): boolean {
  const lower = url.toLowerCase();
  return lower.startsWith("http://") || lower.startsWith("https://");
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
 * Extract any certificates carried inside embedded OCSP responses.
 *
 * OCSP responses frequently bundle the responder certificate and the issuer CA
 * certificate. They are a useful offline source of the issuer certificate needed
 * to build a (live) OCSP request when the container's certificate chain is empty.
 *
 * @param base64Responses Base64-encoded DER OCSP responses (from RevocationValues)
 * @returns PEM-encoded certificates found in the responses
 */
export function extractCertsFromOCSPResponses(base64Responses: string[]): string[] {
  const pems: string[] = [];

  for (const base64Response of base64Responses) {
    try {
      const response = AsnConvert.parse(base64ToArrayBuffer(base64Response), OCSPResponse);
      if (!response.responseBytes) {
        continue;
      }
      const basicResponse = AsnConvert.parse(
        response.responseBytes.response.buffer,
        BasicOCSPResponse,
      );
      for (const certificate of basicResponse.certs ?? []) {
        try {
          const x509 = new X509Certificate(new Uint8Array(AsnConvert.serialize(certificate)));
          pems.push(x509.toString("pem"));
        } catch {
          // Skip certificates that fail to parse
        }
      }
    } catch {
      // Skip responses that fail to parse
    }
  }

  return pems;
}

/**
 * Whether `issuer`'s key verifies the signature on `cert`.
 */
export async function isIssuedBy(cert: X509Certificate, issuer: X509Certificate): Promise<boolean> {
  try {
    return await cert.verify({ publicKey: issuer.publicKey, signatureOnly: true });
  } catch {
    return false;
  }
}

/**
 * Resolve the issuer certificate for a cert from a candidate chain, preferring a
 * candidate whose key actually signed the cert. This avoids building an OCSP
 * request against the wrong (e.g. tampered, same-name) issuer.
 *
 * @param cert Certificate to find the issuer for
 * @param chain Candidate certificates (PEM)
 * @returns The verified issuer certificate, or null
 */
export async function resolveIssuerFromChain(
  cert: X509Certificate,
  chain: string[],
): Promise<X509Certificate | null> {
  const nameMatches: X509Certificate[] = [];
  for (const pemCert of chain) {
    try {
      const candidate = new X509Certificate(pemCert);
      if (candidate.subject === cert.issuer) {
        nameMatches.push(candidate);
      }
    } catch {
      // Skip invalid certificates
    }
  }

  // Prefer a candidate that actually issued the certificate.
  for (const candidate of nameMatches) {
    if (await isIssuedBy(cert, candidate)) {
      return candidate;
    }
  }

  // A same-name certificate with the wrong key must not suppress the safer AIA
  // lookup. Only return a candidate that cryptographically issued the cert.
  return null;
}

/**
 * Fetch issuer certificate from AIA extension. Only a certificate whose key
 * verifies the signature on `cert` is returned.
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
  const urls = extractCAIssuersUrls(cert).slice(0, MAX_URLS_PER_CERTIFICATE);

  for (const url of urls) {
    try {
      const result = await fetchIssuerCertificate(url, timeout, proxyUrl);
      if (result.ok && result.data) {
        let candidate: X509Certificate;
        // Try to parse as DER first, then PEM
        try {
          candidate = new X509Certificate(result.data);
        } catch {
          // Try converting to PEM
          const pem = arrayBufferToPEM(result.data);
          candidate = new X509Certificate(pem);
        }
        if (candidate.subject === cert.issuer && (await isIssuedBy(cert, candidate))) {
          return candidate;
        }
      }
    } catch {
      // Try next URL
    }
  }

  return null;
}

/**
 * Resolve the issuer of a certificate: first from the supplied chain, then via
 * the AIA CA Issuers URLs. Either way the returned issuer has been checked to
 * have signed the certificate.
 */
export async function resolveIssuerCertificate(
  cert: X509Certificate,
  options: { certificateChain?: string[]; timeout?: number; proxyUrl?: string } = {},
): Promise<X509Certificate | null> {
  const { certificateChain = [], timeout = 5000, proxyUrl } = options;
  // The chain may include certs recovered from embedded OCSP responses.
  const fromChain = await resolveIssuerFromChain(cert, certificateChain);
  if (fromChain) {
    return fromChain;
  }
  return fetchIssuerFromAIA(cert, timeout, proxyUrl);
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
  // Parse the raw certificate to get the proper ASN.1 structures for serialization
  const issuerCertAsn = AsnParser.parse(issuerCert.rawData, Certificate);
  const issuerNameDer = AsnConvert.serialize(issuerCertAsn.tbsCertificate.subject);
  const issuerNameHash = await computeSHA1(issuerNameDer);

  // Get issuer key hash (SHA-1 of issuer's public key BIT STRING value, not the full SPKI)
  const issuerKeyHash = await computeSHA1(
    issuerCertAsn.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
  );

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
 * Options for validating an OCSP response
 */
export interface OCSPResponseValidationOptions {
  /** Time to validate against (default: now) */
  now?: Date;
  /** Allowed clock difference in ms (default: REVOCATION_CLOCK_SKEW_MS) */
  clockSkewMs?: number;
  /** Maximum response age when nextUpdate is absent (default: 24h) */
  maxAgeWithoutNextUpdateMs?: number;
}

interface CertificateKeyInfo {
  subjectDer: ArrayBuffer;
  issuerDer: ArrayBuffer;
  subjectPublicKey: ArrayBuffer;
}

function getKeyInfo(cert: X509Certificate): CertificateKeyInfo {
  const asn = AsnParser.parse(cert.rawData, Certificate);
  return {
    subjectDer: AsnConvert.serialize(asn.tbsCertificate.subject),
    issuerDer: AsnConvert.serialize(asn.tbsCertificate.issuer),
    subjectPublicKey: asn.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
  };
}

async function responderIdMatches(rid: ResponderID, cert: X509Certificate): Promise<boolean> {
  try {
    if (rid.byKey) {
      const keyHash = await computeSHA1(getKeyInfo(cert).subjectPublicKey);
      return bytesEqual(keyHash, rid.byKey.buffer);
    }
    if (rid.byName) {
      const nameDer = AsnConvert.serialize(rid.byName);
      if (bytesEqual(nameDer, getKeyInfo(cert).subjectDer)) {
        return true;
      }
      return new Name(nameDer).toString() === cert.subject;
    }
  } catch {
    // fall through
  }
  return false;
}

/**
 * Check that a certificate included in an OCSP response may sign responses on
 * behalf of `issuer` (RFC 6960 section 4.2.2.2). Returns a reason on failure.
 *
 * The responder certificate's own revocation status is not checked. Responder
 * certificates normally carry id-pkix-ocsp-nocheck to indicate that clients
 * need not check them.
 */
async function checkDelegatedResponder(
  responder: X509Certificate,
  issuer: X509Certificate,
  now: Date,
  skewMs: number,
): Promise<string | null> {
  if (responder.issuer !== issuer.subject) {
    return "OCSP responder certificate was not issued by the certificate issuer";
  }
  if (!(await isIssuedBy(responder, issuer))) {
    return "OCSP responder certificate signature does not verify with the issuer key";
  }
  const eku = responder.getExtension(id_ce_extKeyUsage) as ExtendedKeyUsageExtension | null;
  if (!eku || !eku.usages.map(String).includes(id_kp_OCSPSigning)) {
    return "OCSP responder certificate lacks the OCSPSigning extended key usage";
  }
  if (
    responder.notBefore.getTime() > now.getTime() + skewMs ||
    responder.notAfter.getTime() < now.getTime() - skewMs
  ) {
    return "OCSP responder certificate is not valid at the current time";
  }
  return null;
}

async function certIdMatches(
  certId: CertID,
  cert: X509Certificate,
  issuerInfo: CertificateKeyInfo,
  certIssuerDer: ArrayBuffer,
): Promise<boolean> {
  const hashName = CERT_ID_HASH_ALGORITHMS[certId.hashAlgorithm.algorithm];
  if (!hashName) {
    return false;
  }
  if (
    normalizeSerial(arrayBufferToHex(certId.serialNumber)) !== normalizeSerial(cert.serialNumber)
  ) {
    return false;
  }
  const keyHash = await computeDigest(hashName, issuerInfo.subjectPublicKey);
  if (!bytesEqual(keyHash, certId.issuerKeyHash.buffer)) {
    return false;
  }
  const nameHash = await computeDigest(hashName, certIssuerDer);
  if (bytesEqual(nameHash, certId.issuerNameHash.buffer)) {
    return true;
  }
  const issuerSubjectHash = await computeDigest(hashName, issuerInfo.subjectDer);
  return bytesEqual(issuerSubjectHash, certId.issuerNameHash.buffer);
}

/**
 * Parse and validate an OCSP response for `cert`, and extract its revocation status.
 *
 * A "good" or "revoked" result is only returned when:
 * - the response signature verifies,
 * - the signer is the issuing CA itself or a delegated responder certificate
 *   (included in the response) issued by that CA with the OCSPSigning EKU,
 * - a SingleResponse's CertID matches `cert` and `issuer`, and
 * - that SingleResponse is current (thisUpdate/nextUpdate).
 * Otherwise the result is "unknown" or "error" with a reason.
 *
 * @param responseData DER-encoded OCSP response
 * @param cert Certificate the response should be about
 * @param issuer Issuer of `cert`
 * @param options Validation options
 * @returns Revocation result
 */
export async function parseOCSPResponse(
  responseData: ArrayBuffer,
  cert: X509Certificate,
  issuer: X509Certificate,
  options: OCSPResponseValidationOptions = {},
): Promise<RevocationResult> {
  const checkedAt = new Date();
  const now = options.now ?? checkedAt;
  const skewMs = options.clockSkewMs ?? REVOCATION_CLOCK_SKEW_MS;
  const maxAgeMs = options.maxAgeWithoutNextUpdateMs ?? OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_MS;

  const fail = (status: "unknown" | "error", reason: string): RevocationResult => ({
    isValid: false,
    status,
    method: "ocsp",
    reason,
    checkedAt,
  });

  try {
    const response = AsnConvert.parse(responseData, OCSPResponse);

    // Check response status
    switch (response.responseStatus) {
      case OCSPResponseStatus.successful:
        break;
      case OCSPResponseStatus.malformedRequest:
        return fail("error", "OCSP responder returned: malformed request");
      case OCSPResponseStatus.internalError:
        return fail("error", "OCSP responder returned: internal error");
      case OCSPResponseStatus.tryLater:
        return fail("unknown", "OCSP responder returned: try later");
      case OCSPResponseStatus.sigRequired:
        return fail("error", "OCSP responder requires signature");
      case OCSPResponseStatus.unauthorized:
        return fail("error", "OCSP responder returned: unauthorized");
      default:
        return fail("error", `OCSP responder returned unknown status: ${response.responseStatus}`);
    }

    // Parse response bytes
    if (!response.responseBytes) {
      return fail("error", "OCSP response has no response bytes");
    }
    if (response.responseBytes.responseType !== id_pkix_ocsp_basic) {
      return fail(
        "error",
        `Unsupported OCSP response type: ${response.responseBytes.responseType}`,
      );
    }

    // Parse BasicOCSPResponse
    const basicResponse = AsnConvert.parse(
      response.responseBytes.response.buffer,
      BasicOCSPResponse,
    );
    const tbsBytes =
      basicResponse.tbsResponseDataRaw ?? AsnConvert.serialize(basicResponse.tbsResponseData);

    // Identify and authorize the signer, then verify the signature
    const embeddedCerts: X509Certificate[] = [];
    for (const certificate of basicResponse.certs ?? []) {
      try {
        embeddedCerts.push(new X509Certificate(AsnConvert.serialize(certificate)));
      } catch {
        // Skip certificates that fail to parse
      }
    }

    const issuerKeyRaw = issuer.publicKey.rawData;
    const responderId = basicResponse.tbsResponseData.responderID;
    let signerFound = false;
    let signerProblem: string | null = null;

    for (const candidate of [issuer, ...embeddedCerts]) {
      if (!(await responderIdMatches(responderId, candidate))) {
        continue;
      }
      const isIssuerKey = bytesEqual(candidate.publicKey.rawData, issuerKeyRaw);
      if (!isIssuerKey) {
        const problem = await checkDelegatedResponder(candidate, issuer, now, skewMs);
        if (problem) {
          signerProblem = problem;
          continue;
        }
      }
      const signatureOk = await verifyAsnSignature(
        candidate.publicKey,
        basicResponse.signatureAlgorithm,
        basicResponse.signature,
        tbsBytes,
      );
      if (!signatureOk) {
        signerProblem = "OCSP response signature is invalid";
        continue;
      }
      signerFound = true;
      break;
    }

    if (!signerFound) {
      return fail(
        "unknown",
        signerProblem ?? "OCSP response signer is not the issuer or an authorized responder",
      );
    }

    // Select the SingleResponse for this certificate
    const responses = basicResponse.tbsResponseData.responses;
    if (!responses || responses.length === 0) {
      return fail("error", "OCSP response contains no certificate status");
    }

    const issuerInfo = getKeyInfo(issuer);
    const certIssuerDer = getKeyInfo(cert).issuerDer;
    let singleResponse: SingleResponse | undefined;
    for (const candidate of responses) {
      if (await certIdMatches(candidate.certID, cert, issuerInfo, certIssuerDer)) {
        singleResponse = candidate;
        break;
      }
    }
    if (!singleResponse) {
      return fail("unknown", "OCSP response does not contain a status for this certificate");
    }

    // Freshness
    const nowMs = now.getTime();
    if (singleResponse.thisUpdate.getTime() > nowMs + skewMs) {
      return fail("unknown", "OCSP response thisUpdate is in the future");
    }
    if (singleResponse.nextUpdate) {
      if (singleResponse.nextUpdate.getTime() < nowMs - skewMs) {
        return fail(
          "unknown",
          `OCSP response is stale (nextUpdate ${singleResponse.nextUpdate.toISOString()})`,
        );
      }
    } else if (singleResponse.thisUpdate.getTime() < nowMs - maxAgeMs) {
      return fail(
        "unknown",
        `OCSP response is stale (thisUpdate ${singleResponse.thisUpdate.toISOString()})`,
      );
    }

    const certStatus = singleResponse.certStatus;

    // Check certificate status
    if (certStatus.good !== undefined) {
      return {
        isValid: true,
        status: "good",
        method: "ocsp",
        checkedAt,
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
        checkedAt,
      };
    } else if (certStatus.unknown !== undefined) {
      return fail("unknown", "OCSP responder does not know about this certificate");
    }

    return fail("error", "Unexpected certificate status in OCSP response");
  } catch (error) {
    return fail(
      "error",
      `Failed to parse OCSP response: ${error instanceof Error ? error.message : String(error)}`,
    );
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
  options: {
    timeout?: number;
    certificateChain?: string[];
    proxyUrl?: string;
    maxBytes?: number;
  } = {},
): Promise<RevocationResult> {
  const {
    timeout = 5000,
    certificateChain = [],
    proxyUrl,
    maxBytes = DEFAULT_MAX_OCSP_BYTES,
  } = options;
  const now = new Date();

  // Get OCSP URLs
  const ocspUrls = extractOCSPUrls(cert).slice(0, MAX_URLS_PER_CERTIFICATE);
  if (ocspUrls.length === 0) {
    return {
      isValid: false,
      status: "unknown",
      method: "ocsp",
      reason: "Certificate has no OCSP responder URL",
      checkedAt: now,
    };
  }

  // Find the issuer certificate
  let issuer: X509Certificate | null = null;
  if (issuerCert) {
    issuer = (await isIssuedBy(cert, issuerCert)) ? issuerCert : null;
    if (!issuer) {
      return {
        isValid: false,
        status: "unknown",
        method: "ocsp",
        reason: "Supplied issuer certificate did not sign the certificate",
        checkedAt: now,
      };
    }
  } else {
    issuer = await resolveIssuerCertificate(cert, { certificateChain, timeout, proxyUrl });
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

  // Try each OCSP URL; only a validated good/revoked answer is final
  const problems: string[] = [];
  let lastResult: RevocationResult | null = null;
  for (const url of ocspUrls) {
    try {
      const result = await fetchOCSP(url, request, timeout, proxyUrl, maxBytes);
      if (!result.ok || !result.data) {
        problems.push(`${url}: ${result.error || "Failed to fetch"}`);
        continue;
      }
      const parsed = await parseOCSPResponse(result.data, cert, issuer);
      if (parsed.status === "good" || parsed.status === "revoked") {
        return parsed;
      }
      lastResult = parsed;
      problems.push(`${url}: ${parsed.reason ?? parsed.status}`);
    } catch (error) {
      problems.push(`${url}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (lastResult) {
    return {
      ...lastResult,
      reason: problems.length > 1 ? problems.join("; ") : lastResult.reason,
    };
  }

  return {
    isValid: false,
    status: "error",
    method: "ocsp",
    reason: `All OCSP requests failed: ${problems.join("; ")}`,
    checkedAt: now,
  };
}
