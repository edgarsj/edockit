import {
  AuthorityKeyIdentifierExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
} from "@peculiar/x509";
import { findIssuerInChain, fetchIssuerFromAIA } from "../revocation/ocsp";
import { arrayBufferToHex } from "../../utils/encoding";
import { normalizeDistinguishedName, normalizeKeyIdentifier } from "./normalize";
import type { CertificateIdentity, IssuerIdentity, TrustedListFetchOptions } from "./types";

const AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";
const SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";

export interface ExtractIssuerIdentityOptions {
  certificateChain?: string[];
  fetchOptions?: TrustedListFetchOptions;
}

async function computeSha256Hex(input: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", input);
  return arrayBufferToHex(digest);
}

function getAuthorityKeyIdentifierHex(certificate: X509Certificate): string | null {
  const authorityKeyIdentifier = certificate.getExtension(
    AUTHORITY_KEY_IDENTIFIER_OID,
  ) as AuthorityKeyIdentifierExtension | null;

  return normalizeKeyIdentifier(authorityKeyIdentifier?.keyId);
}

function getSubjectKeyIdentifierHex(certificate: X509Certificate): string | null {
  const subjectKeyIdentifier = certificate.getExtension(
    SUBJECT_KEY_IDENTIFIER_OID,
  ) as SubjectKeyIdentifierExtension | null;

  return normalizeKeyIdentifier(subjectKeyIdentifier?.keyId);
}

export async function extractIssuerIdentityFromCertificate(
  certificatePem: string,
  options: ExtractIssuerIdentityOptions = {},
): Promise<IssuerIdentity> {
  const signerCertificate = new X509Certificate(certificatePem);
  let issuerCertificate =
    options.certificateChain && options.certificateChain.length > 0
      ? findIssuerInChain(signerCertificate, options.certificateChain)
      : null;

  if (!issuerCertificate && options.fetchOptions) {
    issuerCertificate = await fetchIssuerFromAIA(
      signerCertificate,
      options.fetchOptions.timeout,
      options.fetchOptions.proxyUrl,
    );
  }

  return {
    issuerSubjectDn: normalizeDistinguishedName(signerCertificate.issuer),
    authorityKeyIdentifierHex: getAuthorityKeyIdentifierHex(signerCertificate),
    issuerCertificate: issuerCertificate
      ? {
          subjectDn: normalizeDistinguishedName(issuerCertificate.subject),
          spkiSha256Hex: await computeSha256Hex(issuerCertificate.publicKey.rawData),
        }
      : null,
  };
}

export async function extractCertificateIdentityFromCertificate(
  certificatePem: string,
): Promise<CertificateIdentity> {
  const certificate = new X509Certificate(certificatePem);

  return {
    subjectDn: normalizeDistinguishedName(certificate.subject),
    subjectKeyIdentifierHex: getSubjectKeyIdentifierHex(certificate),
    spkiSha256Hex: await computeSha256Hex(certificate.publicKey.rawData),
  };
}
