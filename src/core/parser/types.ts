// src/core/parser/types.ts
import { X509Certificate } from "@peculiar/x509";

export interface EdocContainer {
  files: Map<string, Uint8Array>;
  documentFileList: string[]; // All top folder files except metadata
  metadataFileList: string[]; // metadata and META-INF/* files
  signedFileList: string[]; // Files referenced by at least one signature
  signatures: SignatureInfo[];
}

export interface SignatureInfo {
  id: string;
  signingTime: Date;
  certificate: string;
  certificatePEM: string; // Formatted PEM certificate
  certificateChain?: string[]; // Full certificate chain in PEM format (issuer certs)
  publicKey?: {
    algorithm: string; // Algorithm name (RSASSA-PKCS1-v1_5, ECDSA, etc.)
    namedCurve?: string; // For ECDSA keys
    rawData: ArrayBuffer; // Raw public key data
  };
  signedChecksums: Record<string, string>;
  digestAlgorithms?: Record<string, string>; // DigestMethod algorithm per file
  signerInfo?: {
    commonName?: string;
    organization?: string;
    country?: string;
    serialNumber?: string;
    validFrom: Date;
    validTo: Date;
    issuer: {
      commonName?: string;
      organization?: string;
      country?: string;
    };
  };
  references: string[]; // Filenames referenced by this signature
  algorithm?: string; // Signature algorithm URI
  signatureValue?: string; // Base64 signature value
  canonicalSignatureValue?: string; // Canonicalized ds:SignatureValue element (for timestamp verification)
  signedInfoXml?: string; // The XML string of the SignedInfo element
  rawXml?: string; // The full raw XML of the signature
  canonicalizationMethod?: string; // The canonicalization method used
  /** RFC 3161 timestamp token (base64 encoded) from xades:EncapsulatedTimeStamp */
  signatureTimestamp?: string;
  /**
   * Raw embedded XAdES revocation material from
   * xades:UnsignedSignatureProperties/xades:RevocationValues, as base64-encoded DER.
   *
   * NOTE: these values are exposed as-is and are NOT validated by edockit. They live
   * in unsigned signature properties, so unless they are protected by a verified XAdES
   * archive timestamp they are not authenticated and MUST NOT be trusted as a
   * revocation verdict on their own. Verifying them requires checking the OCSP/CRL
   * signature against a trusted issuer and enforcing freshness.
   */
  revocationValues?: {
    /** base64-encoded DER OCSP responses (xades:OCSPValues/EncapsulatedOCSPValue) */
    ocsp: string[];
    /** base64-encoded DER CRLs (xades:CRLValues/EncapsulatedCRLValue) */
    crl: string[];
  };
}
