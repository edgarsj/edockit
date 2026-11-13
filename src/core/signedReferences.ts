// src/core/signedReferences.ts
//
// Verification of same-document (`#id`) references in ds:SignedInfo, most
// importantly the XAdES SignedProperties reference, and of the XAdES
// SigningCertificate binding contained in the signed properties.

import { CANONICALIZATION_METHODS, XMLCanonicalizer } from "./canonicalization/XMLCanonicalizer";
import {
  getCompactText,
  getDsigChildren,
  getSingleDsigChild,
  getSingleXadesChild,
  getXadesChildren,
  isElementNamed,
  isSignedPropertiesReference,
  isXadesElement,
  resolveSameDocumentReference,
} from "./parser/signatureStructure";

const EC_NS = "http://www.w3.org/2001/10/xml-exc-c14n#";

export interface SameDocumentReferenceDetail {
  uri: string;
  type?: string;
  isValid: boolean;
  reason?: string;
}

export interface SignedPropertiesVerificationResult {
  isValid: boolean;
  reason?: string;
  references: SameDocumentReferenceDetail[];
  /** The verified xades:SignedProperties element, if any */
  signedProperties?: Element;
  /** xades:SigningTime from the verified SignedProperties */
  signingTime?: Date;
  /** Whether xades:SigningCertificate(V2) matched the signer certificate */
  signingCertificateMatched?: boolean;
}

function isDescendant(ancestor: Node, node: Node): boolean {
  let current: Node | null = node.parentNode;
  while (current) {
    if (current === ancestor) {
      return true;
    }
    current = current.parentNode;
  }
  return false;
}

type DigestFn = (data: Uint8Array, algorithmUri: string) => Promise<string>;

function getTransformAlgorithms(reference: Element): Element[] {
  const transforms = getSingleDsigChild(reference, "Transforms");
  return transforms ? getDsigChildren(transforms, "Transform") : [];
}

function getInclusiveNamespacePrefixes(transform: Element): string[] | undefined {
  for (let i = 0; i < transform.childNodes.length; i++) {
    const child = transform.childNodes[i];
    if (isElementNamed(child, EC_NS, "InclusiveNamespaces")) {
      const prefixList = (child as Element).getAttribute("PrefixList")?.trim();
      return prefixList ? prefixList.split(/\s+/).filter(Boolean) : undefined;
    }
  }
  return undefined;
}

/**
 * Canonicalize a same-document reference target according to the reference's
 * transforms. Only canonicalization transforms are supported, which covers
 * XAdES SignedProperties references produced by common signing software.
 */
function canonicalizeReferenceTarget(reference: Element, target: Element): string {
  const transforms = getTransformAlgorithms(reference);

  if (transforms.length > 1) {
    throw new Error("Multiple transforms on a same-document reference are not supported");
  }

  if (transforms.length === 0) {
    // XMLDSig: a same-document node-set without transforms is converted to
    // octets using Canonical XML 1.0 (omitting comments).
    return XMLCanonicalizer.canonicalize(target, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
  }

  const algorithm = transforms[0].getAttribute("Algorithm") || "";
  if (!(algorithm in CANONICALIZATION_METHODS) || algorithm === "default") {
    throw new Error(`Unsupported transform on same-document reference: ${algorithm}`);
  }

  // A bare-name reference (#id) dereferences to a node-set without comments,
  // so comments are omitted even for the #WithComments variants
  return XMLCanonicalizer.canonicalize(target, algorithm.replace(/#WithComments$/, ""), {
    inclusiveNamespacePrefixList: getInclusiveNamespacePrefixes(transforms[0]),
  });
}

async function verifySameDocumentReference(
  doc: Document,
  reference: Element,
  digest: DigestFn,
): Promise<{ detail: SameDocumentReferenceDetail; target?: Element }> {
  const uri = reference.getAttribute("URI") || "";
  const type = reference.getAttribute("Type") || undefined;

  try {
    const target = resolveSameDocumentReference(doc, uri);
    const digestMethod = getSingleDsigChild(reference, "DigestMethod", true);
    const digestValue = getSingleDsigChild(reference, "DigestValue", true);
    const algorithmUri = digestMethod.getAttribute("Algorithm") || "";
    const expected = getCompactText(digestValue);
    const canonical = canonicalizeReferenceTarget(reference, target);
    const actual = await digest(new TextEncoder().encode(canonical), algorithmUri);

    if (actual !== expected) {
      return {
        detail: { uri, type, isValid: false, reason: `Digest mismatch for reference "${uri}"` },
      };
    }

    return { detail: { uri, type, isValid: true }, target };
  } catch (error) {
    return {
      detail: {
        uri,
        type,
        isValid: false,
        reason: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

/**
 * Check xades:SigningCertificate / xades:SigningCertificateV2 against the DER
 * encoding of the certificate whose key verified the signature.
 */
async function matchSigningCertificate(
  signedProperties: Element,
  signerCertificateDer: Uint8Array,
  digest: DigestFn,
): Promise<{ matched: boolean; reason?: string }> {
  const signedSignatureProperties = getSingleXadesChild(
    signedProperties,
    "SignedSignatureProperties",
  );
  if (!signedSignatureProperties) {
    return { matched: false, reason: "SignedSignatureProperties not found in SignedProperties" };
  }

  const signingCertificates = [
    ...getXadesChildren(signedSignatureProperties, "SigningCertificateV2"),
    ...getXadesChildren(signedSignatureProperties, "SigningCertificate"),
  ];
  if (signingCertificates.length === 0) {
    return { matched: false, reason: "SigningCertificate not found in SignedProperties" };
  }

  for (const signingCertificate of signingCertificates) {
    for (const cert of getXadesChildren(signingCertificate, "Cert")) {
      const certDigest = getSingleXadesChild(cert, "CertDigest");
      if (!certDigest) {
        continue;
      }
      const digestMethod = getSingleDsigChild(certDigest, "DigestMethod");
      const digestValue = getSingleDsigChild(certDigest, "DigestValue");
      if (!digestMethod || !digestValue) {
        continue;
      }
      try {
        const actual = await digest(
          signerCertificateDer,
          digestMethod.getAttribute("Algorithm") || "",
        );
        if (actual === getCompactText(digestValue)) {
          return { matched: true };
        }
      } catch {
        // Unsupported digest algorithm for this entry; try the next one.
      }
    }
  }

  return {
    matched: false,
    reason: "Signing certificate in SignedProperties does not match the signer certificate",
  };
}

export function readSigningTime(signedProperties: Element): Date | undefined {
  const signedSignatureProperties = getSingleXadesChild(
    signedProperties,
    "SignedSignatureProperties",
  );
  const signingTimeElement = getSingleXadesChild(signedSignatureProperties, "SigningTime");
  const text = signingTimeElement?.textContent?.trim();
  if (!text) {
    return undefined;
  }
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

/**
 * Verify every same-document reference of the given SignedInfo and the XAdES
 * signed properties it covers.
 *
 * Requirements for a valid result:
 * - every `#id` reference resolves to exactly one element and its digest matches
 * - exactly one reference of type SignedProperties exists, pointing to a
 *   xades:SignedProperties element
 * - the SigningCertificate(V2) in the signed properties matches the signer
 *   certificate
 */
export async function verifySignedProperties(
  doc: Document,
  signature: Element,
  references: Element[],
  signerCertificateDer: Uint8Array,
  digest: DigestFn,
): Promise<SignedPropertiesVerificationResult> {
  const details: SameDocumentReferenceDetail[] = [];
  let signedProperties: Element | undefined;
  let signedPropertiesReferenceCount = 0;

  for (const reference of references) {
    const uri = reference.getAttribute("URI") || "";
    if (!uri.startsWith("#")) {
      if (isSignedPropertiesReference(reference)) {
        details.push({
          uri,
          type: reference.getAttribute("Type") || undefined,
          isValid: false,
          reason: "SignedProperties reference must be a same-document reference",
        });
      }
      continue;
    }

    const { detail, target } = await verifySameDocumentReference(doc, reference, digest);
    details.push(detail);

    if (isSignedPropertiesReference(reference)) {
      signedPropertiesReferenceCount += 1;
      if (detail.isValid) {
        if (
          target &&
          isXadesElement(target, "SignedProperties") &&
          isDescendant(signature, target)
        ) {
          signedProperties = target;
        } else {
          detail.isValid = false;
          detail.reason =
            "SignedProperties reference does not point to xades:SignedProperties of this signature";
        }
      }
    }
  }

  const failed = details.find((detail) => !detail.isValid);
  if (failed) {
    return { isValid: false, reason: failed.reason, references: details };
  }

  if (signedPropertiesReferenceCount !== 1 || !signedProperties) {
    return {
      isValid: false,
      reason:
        signedPropertiesReferenceCount === 0
          ? "Signature does not cover SignedProperties"
          : "Signature contains more than one SignedProperties reference",
      references: details,
    };
  }

  const signingCertificate = await matchSigningCertificate(
    signedProperties,
    signerCertificateDer,
    digest,
  );

  return {
    isValid: signingCertificate.matched,
    reason: signingCertificate.reason,
    references: details,
    signedProperties,
    signingTime: readSigningTime(signedProperties),
    signingCertificateMatched: signingCertificate.matched,
  };
}
