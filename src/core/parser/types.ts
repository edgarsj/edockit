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
  signedInfoXml?: string; // The XML string of the SignedInfo element
  rawXml?: string; // The full raw XML of the signature
  canonicalizationMethod?: string; // The canonicalization method used
}
