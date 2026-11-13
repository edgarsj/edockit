// src/core/timestamp/cms.ts
//
// CMS (RFC 5652) SignedData handling for RFC 3161 TimeStampTokens.
//
// Responsibilities:
// - decode the token, keeping the original bytes of the embedded certificates
//   and of the SignerInfo signedAttrs (signatures and ESS certificate hashes are
//   computed over the original encoding, so re-serialized structures must not be
//   used for those)
// - identify the TSA certificate from SignerInfo.sid
// - verify the signed attributes, the ESS signing-certificate binding and the
//   CMS signature using WebCrypto (works in browsers and Node.js)

import * as asn1js from "asn1js";
import { AsnConvert } from "@peculiar/asn1-schema";
import { ContentInfo, SignedData, SignerInfo, SignerIdentifier } from "@peculiar/asn1-cms";
import { TSTInfo } from "@peculiar/asn1-tsp";
import {
  AlgorithmIdentifier,
  Certificate,
  ExtendedKeyUsage,
  Name,
  SubjectKeyIdentifier,
} from "@peculiar/asn1-x509";
import { Name as X509Name } from "@peculiar/x509";
import { fixRSAModulusPadding } from "../rsa-modulus-padding-fix";
import { base64ToArrayBuffer } from "../../utils/encoding";

export const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
export const OID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";

const OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_ATTR_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12";
const OID_ATTR_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
const OID_ATTR_CMS_ALGORITHM_PROTECTION = "1.2.840.113549.1.9.52";

const OID_EXT_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
const OID_EXT_EXTENDED_KEY_USAGE = "2.5.29.37";
const OID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";

const OID_SHA1 = "1.3.14.3.2.26";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

const HASH_OIDS: Record<string, string> = {
  [OID_SHA1]: "SHA-1",
  "2.16.840.1.101.3.4.2.4": "SHA-224",
  [OID_SHA256]: "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
};

const WEBCRYPTO_HASHES = new Set(["SHA-1", "SHA-256", "SHA-384", "SHA-512"]);

const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
const OID_RSASSA_PSS = "1.2.840.113549.1.1.10";
const OID_MGF1 = "1.2.840.113549.1.1.8";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_ED25519 = "1.3.101.112";

const RSA_PKCS1_SIGNATURE_OIDS: Record<string, string> = {
  "1.2.840.113549.1.1.5": "SHA-1",
  "1.2.840.113549.1.1.14": "SHA-224",
  "1.2.840.113549.1.1.11": "SHA-256",
  "1.2.840.113549.1.1.12": "SHA-384",
  "1.2.840.113549.1.1.13": "SHA-512",
};

const ECDSA_SIGNATURE_OIDS: Record<string, string> = {
  "1.2.840.10045.4.1": "SHA-1",
  "1.2.840.10045.4.3.1": "SHA-224",
  "1.2.840.10045.4.3.2": "SHA-256",
  "1.2.840.10045.4.3.3": "SHA-384",
  "1.2.840.10045.4.3.4": "SHA-512",
};

const EC_CURVES: Record<string, { name: string; size: number }> = {
  "1.2.840.10045.3.1.7": { name: "P-256", size: 32 },
  "1.3.132.0.34": { name: "P-384", size: 48 },
  "1.3.132.0.35": { name: "P-521", size: 66 },
};

/**
 * Get hash algorithm name from OID (returns the OID itself when unknown)
 */
export function getHashAlgorithmName(oid: string): string {
  return HASH_OIDS[oid] || oid;
}

/**
 * A certificate together with its original DER encoding
 */
export interface RawCertificate {
  der: Uint8Array;
  certificate: Certificate;
}

/**
 * Decoded RFC 3161 TimeStampToken
 */
export interface DecodedTimestampToken {
  signedData: SignedData;
  signerInfos: SignerInfo[];
  tstInfo: TSTInfo;
  /** eContent octets (DER TSTInfo) */
  tstInfoBytes: Uint8Array;
  /** Original signedAttrs encoding re-tagged as SET OF (0x31), if present */
  signedAttrsDer?: Uint8Array;
  /** Certificates carried in the token, with their original encoding */
  certificates: RawCertificate[];
}

function toUint8Array(data: ArrayBuffer | ArrayBufferView): Uint8Array {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  return bytes.subarray(start);
}

function isContextTag(block: asn1js.AsnType, tagNumber: number): boolean {
  return block.idBlock.tagClass === 3 && block.idBlock.tagNumber === tagNumber;
}

function isUniversalSequence(block: asn1js.AsnType): boolean {
  return block.idBlock.tagClass === 1 && block.idBlock.tagNumber === 16;
}

function childrenOf(block: asn1js.AsnType): asn1js.AsnType[] {
  const value = (block as asn1js.Constructed).valueBlock?.value;
  return Array.isArray(value) ? (value as asn1js.AsnType[]) : [];
}

/**
 * Extract the original encodings of the embedded certificates and of the first
 * SignerInfo's signedAttrs from the token bytes.
 */
function extractRawParts(tokenBytes: ArrayBuffer): {
  certificates: Uint8Array[];
  signedAttrsDer?: Uint8Array;
} {
  const parsed = asn1js.fromBER(tokenBytes);
  if (parsed.offset === -1) {
    throw new Error(`Invalid timestamp token encoding: ${parsed.result.error}`);
  }

  // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT content }
  const contentInfoChildren = childrenOf(parsed.result);
  const explicitContent = contentInfoChildren.find((c) => isContextTag(c, 0));
  const signedData = explicitContent ? childrenOf(explicitContent)[0] : undefined;
  if (!signedData) {
    throw new Error("Timestamp token does not contain SignedData content");
  }

  // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
  //   certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos }
  const signedDataChildren = childrenOf(signedData);
  const certificates: Uint8Array[] = [];
  const certSet = signedDataChildren.find((c) => isContextTag(c, 0));
  if (certSet) {
    for (const cert of childrenOf(certSet)) {
      // Only plain X.509 certificates (other CertificateChoices are tagged)
      if (isUniversalSequence(cert)) {
        certificates.push(new Uint8Array(cert.valueBeforeDecodeView).slice());
      }
    }
  }

  let signedAttrsDer: Uint8Array | undefined;
  const signerInfos = signedDataChildren[signedDataChildren.length - 1];
  const firstSignerInfo = signerInfos ? childrenOf(signerInfos)[0] : undefined;
  if (firstSignerInfo) {
    // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
    //   signedAttrs [0] IMPLICIT OPTIONAL, signatureAlgorithm, signature, ... }
    const signerChildren = childrenOf(firstSignerInfo);
    // sid itself may be [0] (subjectKeyIdentifier), so skip the first 3 fields
    const attrs = signerChildren.slice(3).find((c) => isContextTag(c, 0));
    if (attrs) {
      signedAttrsDer = new Uint8Array(attrs.valueBeforeDecodeView).slice();
      // The signature is computed over the DER encoding of SET OF Attribute
      signedAttrsDer[0] = 0x31;
    }
  }

  return { certificates, signedAttrsDer };
}

/**
 * Decode an RFC 3161 TimeStampToken. Throws on structural errors.
 */
export function decodeTimestampToken(timestampBase64: string): DecodedTimestampToken {
  const tokenBuffer = base64ToArrayBuffer(timestampBase64);

  // TimeStampToken ::= ContentInfo
  const contentInfo = AsnConvert.parse(tokenBuffer, ContentInfo);
  if (contentInfo.contentType !== OID_SIGNED_DATA) {
    throw new Error("Timestamp is not SignedData");
  }

  const signedData = AsnConvert.parse(contentInfo.content, SignedData);
  if (signedData.encapContentInfo.eContentType !== OID_CT_TST_INFO) {
    throw new Error("SignedData does not contain TSTInfo");
  }

  const eContent = signedData.encapContentInfo.eContent;
  if (!eContent) {
    throw new Error("No eContent in SignedData");
  }

  // EncapsulatedContent may be in .single (OctetString) or .any (ArrayBuffer)
  let tstInfoBuffer: ArrayBuffer;
  if (eContent.single) {
    tstInfoBuffer = eContent.single.buffer;
  } else if (eContent.any) {
    tstInfoBuffer = eContent.any;
  } else {
    tstInfoBuffer = AsnConvert.serialize(eContent);
  }

  const tstInfo = AsnConvert.parse(tstInfoBuffer, TSTInfo);
  const raw = extractRawParts(tokenBuffer);

  return {
    signedData,
    signerInfos: Array.from(signedData.signerInfos),
    tstInfo,
    tstInfoBytes: toUint8Array(tstInfoBuffer).slice(),
    signedAttrsDer: raw.signedAttrsDer,
    certificates: raw.certificates.map((der) => ({
      der,
      certificate: AsnConvert.parse(toArrayBuffer(der), Certificate),
    })),
  };
}

/**
 * Parse a certificate given as PEM, base64 DER, or binary DER
 */
export function toRawCertificate(input: string | ArrayBuffer | Uint8Array): RawCertificate {
  let der: Uint8Array;
  if (typeof input === "string") {
    const base64 = input
      .replace(/-----BEGIN [^-]+-----/g, "")
      .replace(/-----END [^-]+-----/g, "")
      .replace(/\s+/g, "");
    der = new Uint8Array(base64ToArrayBuffer(base64));
  } else {
    der = toUint8Array(input).slice();
  }
  return { der, certificate: AsnConvert.parse(toArrayBuffer(der), Certificate) };
}

function getExtensionValue(certificate: Certificate, oid: string): ArrayBuffer | undefined {
  const ext = certificate.tbsCertificate.extensions?.find((e) => e.extnID === oid);
  return ext ? ext.extnValue.buffer : undefined;
}

function namesMatch(a: Name, b: Name): boolean {
  const derA = new Uint8Array(AsnConvert.serialize(a));
  const derB = new Uint8Array(AsnConvert.serialize(b));
  if (bytesEqual(derA, derB)) {
    return true;
  }
  // Tolerate differences in string encoding of otherwise identical names
  try {
    return (
      new X509Name(derA).toString().toLowerCase() === new X509Name(derB).toString().toLowerCase()
    );
  } catch {
    return false;
  }
}

/**
 * Check whether a certificate is the one referenced by a SignerIdentifier
 */
export function certificateMatchesSignerId(
  certificate: Certificate,
  sid: SignerIdentifier,
): boolean {
  if (sid.issuerAndSerialNumber) {
    const tbs = certificate.tbsCertificate;
    const serialMatches = bytesEqual(
      stripLeadingZeros(toUint8Array(tbs.serialNumber)),
      stripLeadingZeros(toUint8Array(sid.issuerAndSerialNumber.serialNumber)),
    );
    return serialMatches && namesMatch(tbs.issuer, sid.issuerAndSerialNumber.issuer);
  }

  if (sid.subjectKeyIdentifier) {
    const skiValue = getExtensionValue(certificate, OID_EXT_SUBJECT_KEY_IDENTIFIER);
    if (!skiValue) {
      return false;
    }
    const ski = AsnConvert.parse(skiValue, SubjectKeyIdentifier);
    return bytesEqual(toUint8Array(ski.buffer), toUint8Array(sid.subjectKeyIdentifier.buffer));
  }

  return false;
}

/**
 * Find the certificate identified by a SignerIdentifier
 */
export function findSignerCertificate(
  sid: SignerIdentifier,
  candidates: RawCertificate[],
): RawCertificate | undefined {
  return candidates.find((c) => {
    try {
      return certificateMatchesSignerId(c.certificate, sid);
    } catch {
      return false;
    }
  });
}

/**
 * Check that a certificate carries the id-kp-timeStamping extended key usage
 */
export function hasTimeStampingKeyUsage(certificate: Certificate): boolean {
  const ekuValue = getExtensionValue(certificate, OID_EXT_EXTENDED_KEY_USAGE);
  if (!ekuValue) {
    return false;
  }
  try {
    const eku = AsnConvert.parse(ekuValue, ExtendedKeyUsage);
    return Array.from(eku).includes(OID_KP_TIME_STAMPING);
  } catch {
    return false;
  }
}

function getSubtle(): SubtleCrypto {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto API (crypto.subtle) is not available");
  }
  return subtle;
}

async function digest(hashName: string, data: Uint8Array): Promise<Uint8Array> {
  if (!WEBCRYPTO_HASHES.has(hashName)) {
    throw new Error(`Unsupported hash algorithm: ${hashName}`);
  }
  return new Uint8Array(await getSubtle().digest(hashName, toArrayBuffer(data)));
}

function findAttribute(signerInfo: SignerInfo, oid: string) {
  return signerInfo.signedAttrs?.filter((a) => a.attrType === oid) ?? [];
}

function parseDer(data: ArrayBuffer | Uint8Array): asn1js.AsnType {
  const buffer = data instanceof Uint8Array ? toArrayBuffer(data) : data;
  const parsed = asn1js.fromBER(buffer);
  if (parsed.offset === -1) {
    throw new Error(`Invalid ASN.1 encoding: ${parsed.result.error}`);
  }
  return parsed.result;
}

function readOid(block: asn1js.AsnType | undefined): string | undefined {
  return block instanceof asn1js.ObjectIdentifier ? block.valueBlock.toString() : undefined;
}

function readOctets(block: asn1js.AsnType | undefined): Uint8Array | undefined {
  if (!(block instanceof asn1js.OctetString)) {
    return undefined;
  }
  return new Uint8Array(block.valueBlock.valueHexView).slice();
}

/**
 * Check a SigningCertificate / SigningCertificateV2 attribute against the TSA certificate.
 * Per RFC 5035 the first ESSCertID identifies the signing certificate.
 */
async function checkSigningCertificateAttribute(
  value: ArrayBuffer,
  version: 1 | 2,
  certificateDer: Uint8Array,
): Promise<string | undefined> {
  const label = version === 1 ? "SigningCertificate" : "SigningCertificateV2";
  // SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies OPTIONAL }
  const certs = childrenOf(parseDer(value))[0];
  const firstCertId = certs ? childrenOf(certs)[0] : undefined;
  if (!firstCertId) {
    return `${label} attribute does not contain a certificate identifier`;
  }

  const fields = childrenOf(firstCertId);
  let hashName = "SHA-1";
  let certHash: Uint8Array | undefined;

  if (version === 1) {
    // ESSCertID ::= SEQUENCE { certHash OCTET STRING (SHA-1), issuerSerial OPTIONAL }
    certHash = readOctets(fields[0]);
  } else {
    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash, issuerSerial OPTIONAL }
    if (fields[0] && isUniversalSequence(fields[0])) {
      const hashOid = readOid(childrenOf(fields[0])[0]);
      hashName = hashOid ? getHashAlgorithmName(hashOid) : "";
      certHash = readOctets(fields[1]);
    } else {
      hashName = "SHA-256";
      certHash = readOctets(fields[0]);
    }
  }

  if (!certHash) {
    return `${label} attribute is malformed`;
  }
  if (!WEBCRYPTO_HASHES.has(hashName)) {
    return `${label} attribute uses an unsupported hash algorithm`;
  }

  const actual = await digest(hashName, certificateDer);
  if (!bytesEqual(actual, certHash)) {
    return `${label} attribute does not match the TSA certificate`;
  }
  return undefined;
}

/**
 * Check the CMSAlgorithmProtection attribute (RFC 6211), if present
 */
function checkAlgorithmProtectionAttribute(
  value: ArrayBuffer,
  signerInfo: SignerInfo,
): string | undefined {
  // CMSAlgorithmProtection ::= SEQUENCE { digestAlgorithm,
  //   signatureAlgorithm [1] IMPLICIT OPTIONAL, macAlgorithm [2] IMPLICIT OPTIONAL }
  const fields = childrenOf(parseDer(value));
  const digestOid = fields[0] ? readOid(childrenOf(fields[0])[0]) : undefined;
  if (digestOid !== signerInfo.digestAlgorithm.algorithm) {
    return "CMSAlgorithmProtection digest algorithm does not match SignerInfo";
  }
  const sigAlg = fields.find((f) => isContextTag(f, 1));
  if (sigAlg) {
    const sigOid = readOid(childrenOf(sigAlg)[0]);
    if (sigOid !== signerInfo.signatureAlgorithm.algorithm) {
      return "CMSAlgorithmProtection signature algorithm does not match SignerInfo";
    }
  }
  return undefined;
}

interface ResolvedSignatureAlgorithm {
  kind: "RSASSA-PKCS1-v1_5" | "RSA-PSS" | "ECDSA" | "Ed25519";
  hash?: string;
  saltLength?: number;
}

function parsePssParams(parameters: ArrayBuffer | null | undefined): {
  hash: string;
  saltLength: number;
} {
  // RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0] DEFAULT sha1,
  //   maskGenAlgorithm [1] DEFAULT mgf1SHA1, saltLength [2] DEFAULT 20, trailerField [3] DEFAULT 1 }
  let hashOid = OID_SHA1;
  let mgfHashOid = OID_SHA1;
  let saltLength = 20;

  if (parameters && parameters.byteLength > 0) {
    for (const field of childrenOf(parseDer(parameters))) {
      const inner = childrenOf(field)[0];
      if (isContextTag(field, 0)) {
        hashOid = readOid(childrenOf(inner)[0]) ?? hashOid;
      } else if (isContextTag(field, 1)) {
        const [mgfOid, mgfParams] = childrenOf(inner);
        if (readOid(mgfOid) !== OID_MGF1) {
          throw new Error("Unsupported RSA-PSS mask generation function");
        }
        mgfHashOid = readOid(childrenOf(mgfParams)[0]) ?? mgfHashOid;
      } else if (isContextTag(field, 2)) {
        if (!(inner instanceof asn1js.Integer)) {
          throw new Error("Invalid RSA-PSS salt length");
        }
        saltLength = inner.valueBlock.valueDec;
      }
    }
  }

  if (hashOid !== mgfHashOid) {
    throw new Error("RSA-PSS with differing MGF1 hash is not supported");
  }
  return { hash: getHashAlgorithmName(hashOid), saltLength };
}

function resolveSignatureAlgorithm(
  signatureAlgorithm: AlgorithmIdentifier,
  digestHash: string,
): ResolvedSignatureAlgorithm {
  const oid = signatureAlgorithm.algorithm;
  if (oid === OID_RSA_ENCRYPTION) {
    return { kind: "RSASSA-PKCS1-v1_5", hash: digestHash };
  }
  if (RSA_PKCS1_SIGNATURE_OIDS[oid]) {
    return { kind: "RSASSA-PKCS1-v1_5", hash: RSA_PKCS1_SIGNATURE_OIDS[oid] };
  }
  if (oid === OID_RSASSA_PSS) {
    const { hash, saltLength } = parsePssParams(signatureAlgorithm.parameters);
    return { kind: "RSA-PSS", hash, saltLength };
  }
  if (oid === OID_EC_PUBLIC_KEY) {
    return { kind: "ECDSA", hash: digestHash };
  }
  if (ECDSA_SIGNATURE_OIDS[oid]) {
    return { kind: "ECDSA", hash: ECDSA_SIGNATURE_OIDS[oid] };
  }
  if (oid === OID_ED25519) {
    return { kind: "Ed25519" };
  }
  throw new Error(`Unsupported signature algorithm: ${oid}`);
}

/**
 * Convert a DER-encoded ECDSA-Sig-Value to the raw r||s form used by WebCrypto
 */
export function ecdsaDerToRaw(der: Uint8Array, componentSize: number): Uint8Array {
  const seq = parseDer(der);
  const [r, s] = childrenOf(seq);
  if (!(r instanceof asn1js.Integer) || !(s instanceof asn1js.Integer)) {
    throw new Error("Invalid ECDSA signature encoding");
  }
  const out = new Uint8Array(componentSize * 2);
  [r, s].forEach((component, index) => {
    const bytes = stripLeadingZeros(new Uint8Array(component.valueBlock.valueHexView));
    if (bytes.length > componentSize) {
      throw new Error("Invalid ECDSA signature component length");
    }
    out.set(bytes, componentSize * (index + 1) - bytes.length);
  });
  return out;
}

async function verifyWithPublicKey(
  certificate: Certificate,
  algorithm: ResolvedSignatureAlgorithm,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const subtle = getSubtle();
  const spki = certificate.tbsCertificate.subjectPublicKeyInfo;
  const spkiDer = AsnConvert.serialize(spki);
  const keyOid = spki.algorithm.algorithm;

  if (algorithm.hash && !WEBCRYPTO_HASHES.has(algorithm.hash)) {
    throw new Error(`Unsupported hash algorithm: ${algorithm.hash}`);
  }

  switch (algorithm.kind) {
    case "RSASSA-PKCS1-v1_5":
    case "RSA-PSS": {
      if (keyOid !== OID_RSA_ENCRYPTION && keyOid !== OID_RSASSA_PSS) {
        throw new Error("TSA certificate key does not match the RSA signature algorithm");
      }
      const importParams = { name: algorithm.kind, hash: algorithm.hash as string };
      let key: CryptoKey;
      try {
        key = await subtle.importKey("spki", spkiDer, importParams, false, ["verify"]);
      } catch {
        // Some certificates carry an RSA modulus without the required leading zero
        const fixedKey = fixRSAModulusPadding(spkiDer);
        key = await subtle.importKey("spki", fixedKey, importParams, false, ["verify"]);
      }
      const verifyParams =
        algorithm.kind === "RSA-PSS"
          ? { name: "RSA-PSS", saltLength: algorithm.saltLength as number }
          : { name: "RSASSA-PKCS1-v1_5" };
      // Strict verification only: unlike XML signatures from old signing tools,
      // TSA tokens are not expected to carry non-standard DigestInfo encodings.
      return subtle.verify(verifyParams, key, toArrayBuffer(signature), toArrayBuffer(data));
    }
    case "ECDSA": {
      if (keyOid !== OID_EC_PUBLIC_KEY) {
        throw new Error("TSA certificate key does not match the ECDSA signature algorithm");
      }
      const curveOid = spki.algorithm.parameters
        ? readOid(parseDer(spki.algorithm.parameters))
        : undefined;
      const curve = curveOid ? EC_CURVES[curveOid] : undefined;
      if (!curve) {
        throw new Error(`Unsupported elliptic curve: ${curveOid ?? "unknown"}`);
      }
      const key = await subtle.importKey(
        "spki",
        spkiDer,
        { name: "ECDSA", namedCurve: curve.name },
        false,
        ["verify"],
      );
      const rawSignature = ecdsaDerToRaw(signature, curve.size);
      return subtle.verify(
        { name: "ECDSA", hash: algorithm.hash as string },
        key,
        toArrayBuffer(rawSignature),
        toArrayBuffer(data),
      );
    }
    case "Ed25519": {
      if (keyOid !== OID_ED25519) {
        throw new Error("TSA certificate key does not match the Ed25519 signature algorithm");
      }
      const key = await subtle.importKey("spki", spkiDer, { name: "Ed25519" }, false, ["verify"]);
      return subtle.verify({ name: "Ed25519" }, key, toArrayBuffer(signature), toArrayBuffer(data));
    }
  }
}

/**
 * Result of verifying the CMS layer of a TimeStampToken
 */
export interface TokenSignatureVerification {
  /** The certificate identified by SignerInfo.sid (if found) */
  tsaCertificate?: RawCertificate;
  /**
   * True when the CMS signature and signed attributes (content-type,
   * message-digest, signing-certificate binding) verify against tsaCertificate
   */
  signatureValid: boolean;
  /** Whether tsaCertificate carries the id-kp-timeStamping extended key usage */
  hasTimeStampingUsage?: boolean;
  /** Reason when signatureValid is false */
  reason?: string;
}

/**
 * Verify the CMS SignedData signature of a decoded TimeStampToken.
 *
 * @param token Decoded token
 * @param extraCertificates Additional candidate certificates for locating the TSA
 *   certificate (e.g. from XAdES CertificateValues) when the token does not embed it
 */
export async function verifyTokenSignature(
  token: DecodedTimestampToken,
  extraCertificates: RawCertificate[] = [],
): Promise<TokenSignatureVerification> {
  // RFC 3161 2.4.2: the token must have exactly one signer
  if (token.signerInfos.length !== 1) {
    return {
      signatureValid: false,
      reason: `Timestamp token must contain exactly one SignerInfo (found ${token.signerInfos.length})`,
    };
  }
  const signerInfo = token.signerInfos[0];

  const tsaCertificate = findSignerCertificate(signerInfo.sid, [
    ...token.certificates,
    ...extraCertificates,
  ]);
  if (!tsaCertificate) {
    return {
      signatureValid: false,
      reason: "TSA certificate referenced by the timestamp SignerInfo was not found",
    };
  }

  const hasTimeStampingUsage = hasTimeStampingKeyUsage(tsaCertificate.certificate);
  const fail = (reason: string): TokenSignatureVerification => ({
    tsaCertificate,
    signatureValid: false,
    hasTimeStampingUsage,
    reason,
  });

  try {
    const digestHash = getHashAlgorithmName(signerInfo.digestAlgorithm.algorithm);
    let signedBytes: Uint8Array;

    if (signerInfo.signedAttrs && signerInfo.signedAttrs.length > 0) {
      if (!token.signedAttrsDer) {
        return fail("Could not locate the encoded signed attributes");
      }

      // content-type attribute must be present and equal id-ct-TSTInfo
      const contentType = findAttribute(signerInfo, OID_ATTR_CONTENT_TYPE);
      if (contentType.length !== 1 || contentType[0].attrValues.length !== 1) {
        return fail("Timestamp signed attributes must contain exactly one content-type");
      }
      if (readOid(parseDer(contentType[0].attrValues[0])) !== OID_CT_TST_INFO) {
        return fail("Timestamp content-type attribute is not id-ct-TSTInfo");
      }

      // message-digest attribute must match the hash of the TSTInfo
      const messageDigest = findAttribute(signerInfo, OID_ATTR_MESSAGE_DIGEST);
      if (messageDigest.length !== 1 || messageDigest[0].attrValues.length !== 1) {
        return fail("Timestamp signed attributes must contain exactly one message-digest");
      }
      const expectedDigest = readOctets(parseDer(messageDigest[0].attrValues[0]));
      const actualDigest = await digest(digestHash, token.tstInfoBytes);
      if (!expectedDigest || !bytesEqual(expectedDigest, actualDigest)) {
        return fail("Timestamp message-digest does not match the TSTInfo content");
      }

      const algorithmProtection = findAttribute(signerInfo, OID_ATTR_CMS_ALGORITHM_PROTECTION);
      if (algorithmProtection.length > 0) {
        const problem = checkAlgorithmProtectionAttribute(
          algorithmProtection[0].attrValues[0],
          signerInfo,
        );
        if (problem) {
          return fail(problem);
        }
      }

      // ESS signing-certificate binding (RFC 2634 / RFC 5035), checked when present
      for (const [oid, version] of [
        [OID_ATTR_SIGNING_CERTIFICATE, 1],
        [OID_ATTR_SIGNING_CERTIFICATE_V2, 2],
      ] as const) {
        const attr = findAttribute(signerInfo, oid);
        if (attr.length > 0) {
          const problem = await checkSigningCertificateAttribute(
            attr[0].attrValues[0],
            version,
            tsaCertificate.der,
          );
          if (problem) {
            return fail(problem);
          }
        }
      }

      signedBytes = token.signedAttrsDer;
    } else {
      signedBytes = token.tstInfoBytes;
    }

    const algorithm = resolveSignatureAlgorithm(signerInfo.signatureAlgorithm, digestHash);
    const valid = await verifyWithPublicKey(
      tsaCertificate.certificate,
      algorithm,
      toUint8Array(signerInfo.signature.buffer),
      signedBytes,
    );
    if (!valid) {
      return fail("Timestamp token signature is invalid");
    }

    return { tsaCertificate, signatureValid: true, hasTimeStampingUsage };
  } catch (error) {
    return fail(
      `Timestamp token signature could not be verified: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
