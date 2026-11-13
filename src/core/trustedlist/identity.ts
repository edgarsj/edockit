import {
  AuthorityKeyIdentifierExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
} from "@peculiar/x509";
import { fetchIssuerFromAIA, resolveIssuerFromChain } from "../revocation/ocsp";
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

async function isIssuedBy(certificate: X509Certificate, issuer: X509Certificate): Promise<boolean> {
  try {
    return (
      certificate.issuer === issuer.subject &&
      (await certificate.verify({ publicKey: issuer, signatureOnly: true }))
    );
  } catch {
    return false;
  }
}

/**
 * Derive the issuer identity of a certificate for trusted-list matching.
 *
 * `issuerCertificate` is only populated with a certificate whose key verifies
 * the signature on `certificatePem`; candidates from the chain or from AIA
 * that merely carry the issuer's name are ignored.
 */
export async function extractIssuerIdentityFromCertificate(
  certificatePem: string,
  options: ExtractIssuerIdentityOptions = {},
): Promise<IssuerIdentity> {
  const signerCertificate = new X509Certificate(certificatePem);
  let issuerCertificate =
    options.certificateChain && options.certificateChain.length > 0
      ? await resolveIssuerFromChain(signerCertificate, options.certificateChain)
      : null;
  let rejectedIssuerCandidate = false;

  if (!issuerCertificate) {
    rejectedIssuerCandidate = (options.certificateChain ?? []).some((pem) => {
      try {
        return new X509Certificate(pem).subject === signerCertificate.issuer;
      } catch {
        return false;
      }
    });
  }

  if (!issuerCertificate && options.fetchOptions) {
    const fetched = await fetchIssuerFromAIA(
      signerCertificate,
      options.fetchOptions.timeout,
      options.fetchOptions.proxyUrl,
    );
    if (fetched && (await isIssuedBy(signerCertificate, fetched))) {
      issuerCertificate = fetched;
    } else if (fetched && fetched.subject === signerCertificate.issuer) {
      rejectedIssuerCandidate = true;
    }
  }

  return {
    issuerSubjectDn: normalizeDistinguishedName(signerCertificate.issuer),
    authorityKeyIdentifierHex: getAuthorityKeyIdentifierHex(signerCertificate),
    ...(issuerCertificate ? {} : { issuerSignatureMismatch: rejectedIssuerCandidate }),
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
