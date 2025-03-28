// src/core/parser/types.ts
import { X509Certificate } from "@peculiar/x509";

// Types for the parsed eDoc container
export interface EdocContainer {
  files: Map<string, Uint8Array>;
  signatures: SignatureInfo[];
}

export interface SignatureInfo {
  id: string;
  signingTime: Date;
  certificate: string;
  certificatePEM: string; // Formatted PEM certificate
  publicKey?: {
    algorithm: string; // Algorithm name (RSASSA-PKCS1-v1_5, ECDSA, etc.)
    namedCurve?: string; // For ECDSA keys
    rawData: ArrayBuffer; // Raw public key data
  };
  signedChecksums: Record<string, string>;
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
