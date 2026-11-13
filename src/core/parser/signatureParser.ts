// src/core/parser/signatureParser.ts
import { X509Certificate } from "@peculiar/x509";
import * as XmlParserModule from "../../utils/xmlParser";

import { createXMLParser } from "../../utils/xmlParser";
import { XMLCanonicalizer, CANONICALIZATION_METHODS } from "../canonicalization/XMLCanonicalizer";
import { extractSignerInfo } from "../certificate";
import { SignatureInfo } from "./types";
import { formatPEM } from "./certificateUtils";
import {
  getChildElements,
  getCompactText,
  getDsigChildren,
  getUnsignedSignatureProperties,
  getXadesChildren,
  getSignatureParts,
  getSingleDsigChild,
  isSignedPropertiesReference,
  locateTopLevelSignatures,
  resolveSameDocumentReference,
} from "./signatureStructure";
import { readSigningTime } from "../signedReferences";

function parseInclusiveNamespacesPrefixList(
  canonicalizationMethodElement: Element | null,
): string[] | undefined {
  if (!canonicalizationMethodElement) {
    return undefined;
  }

  const inclusiveNamespacesElement = getChildElements(canonicalizationMethodElement).find(
    (child) => child.localName === "InclusiveNamespaces",
  );
  const prefixList = inclusiveNamespacesElement?.getAttribute("PrefixList")?.trim();

  if (!prefixList) {
    return undefined;
  }

  const prefixes = prefixList.split(/\s+/).filter(Boolean);
  return prefixes.length > 0 ? prefixes : undefined;
}

function createTimestampCanonicalizer(canonicalizationMethod?: string): XMLCanonicalizer {
  if (!canonicalizationMethod) {
    return new XMLCanonicalizer();
  }

  try {
    return XMLCanonicalizer.fromMethod(canonicalizationMethod);
  } catch {
    // Fall back to default canonicalization so timestamp binding is still attempted
    // instead of being skipped entirely for unsupported URI variants.
    return new XMLCanonicalizer();
  }
}

/**
 * Find signature files in the eDoc container
 * @param files Map of filenames to file contents
 * @returns Array of signature filenames
 */
export function findSignatureFiles(files: Map<string, Uint8Array>): string[] {
  // Signature files are typically named with patterns like:
  // - signatures0.xml
  // - META-INF/signatures*.xml
  return Array.from(files.keys()).filter(
    (filename) =>
      filename.match(/META-INF\/signatures\d*\.xml$/) ||
      filename.match(/META-INF\/.*signatures.*\.xml$/i),
  );
}

/**
 * Parse a signature file that contains a single signature
 * @param xmlContent The XML file content
 * @param filename The filename (for reference)
 * @returns The parsed signature with raw XML content
 */
export function parseSignatureFile(xmlContent: Uint8Array, filename: string): SignatureInfo | null {
  const text = new TextDecoder().decode(xmlContent);
  const parser = createXMLParser();
  const xmlDoc = parser.parseFromString(text, "application/xml");

  // Only a ds:Signature that is the document element or a direct child of it is
  // the document's signature (nested signatures are never selected).
  const signatureElements = locateTopLevelSignatures(xmlDoc);

  if (signatureElements.length === 0) {
    console.warn(`No Signature elements found in ${filename}`);
    return null;
  }

  // Parse the signature and add the raw XML
  let signatureInfo = parseSignatureElement(signatureElements[0], xmlDoc);
  signatureInfo.rawXml = text;
  return signatureInfo;
}

/**
 * Parse a single signature element using a browser-like approach
 * @param signatureElement The signature element to parse
 * @param xmlDoc The parent XML document
 * @returns Parsed signature information
 */
export function parseSignatureElement(signatureElement: Element, xmlDoc: Document): SignatureInfo {
  // Get signature ID
  const signatureId = signatureElement.getAttribute("Id") || "unknown";
  // Resolve SignedInfo, SignatureValue and KeyInfo strictly as direct children
  // of this ds:Signature, so verification always uses the same SignedInfo whose
  // references are reported here.
  const parts = getSignatureParts(signatureElement);
  const signedInfo = parts.signedInfo;

  // Get the canonicalization method
  const c14nMethodEl = getSingleDsigChild(signedInfo, "CanonicalizationMethod");
  let canonicalizationMethod = CANONICALIZATION_METHODS.default;
  if (c14nMethodEl) {
    canonicalizationMethod = c14nMethodEl.getAttribute("Algorithm") || canonicalizationMethod;
  }

  // // Serialize the SignedInfo element to XML string
  // let signedInfoXml = "";
  // try {
  //   // Use the serializeToXML utility function which handles browser/Node environments
  //   signedInfoXml = serializeToXML(signedInfo);
  // } catch (e) {
  //   console.warn("Could not serialize SignedInfo element:", e);
  // }

  // Serialize the SignedInfo element to XML string
  let signedInfoXml = "";
  signedInfoXml = XmlParserModule.serializeToXML(signedInfo);

  // try {
  //   // First check if signedInfo is a valid node
  //   if (!signedInfo) {
  //     console.warn("SignedInfo element is undefined or null");
  //     signedInfoXml = "";
  //   } else if (signedInfo.nodeType === undefined) {
  //     console.warn("SignedInfo doesn't appear to be a valid XML node:", signedInfo);
  //     signedInfoXml = "";
  //   } else {
  //     // Try to use XMLSerializer if available in browser
  //     if (typeof window !== "undefined" && window.XMLSerializer) {
  //       signedInfoXml = new window.XMLSerializer().serializeToString(signedInfo);
  //     } else {
  //       // Node.js environment - use xmldom only
  //       const xmldom = require("@xmldom/xmldom");
  //       const serializer = new xmldom.XMLSerializer();
  //       signedInfoXml = serializer.serializeToString(signedInfo);
  //     }
  //   }
  // } catch (e) {
  //   console.warn("Could not serialize SignedInfo element:", e);
  // }

  // Get signature method
  const signatureMethod = getSingleDsigChild(signedInfo, "SignatureMethod");
  const signatureAlgorithm = signatureMethod?.getAttribute("Algorithm") || "";

  // Get signature value
  const signatureValueEl = parts.signatureValue;
  const signatureValue = getCompactText(signatureValueEl);

  // Extract signature timestamp (RFC 3161) and its canonicalization method
  let signatureTimestamp: string | undefined;
  let signatureTimestampCanonicalizationMethod: string | undefined;
  let signatureTimestampInclusiveNamespacePrefixList: string[] | undefined;
  const unsignedSignatureProperties = getUnsignedSignatureProperties(signatureElement);
  const signatureTimestampElement =
    getXadesChildren(unsignedSignatureProperties, "SignatureTimeStamp")[0] ?? null;
  if (signatureTimestampElement) {
    const timestampC14nMethodEl = getSingleDsigChild(
      signatureTimestampElement,
      "CanonicalizationMethod",
    );
    signatureTimestampCanonicalizationMethod =
      timestampC14nMethodEl?.getAttribute("Algorithm") || undefined;
    signatureTimestampInclusiveNamespacePrefixList =
      parseInclusiveNamespacesPrefixList(timestampC14nMethodEl);

    const timestampElement =
      getXadesChildren(signatureTimestampElement, "EncapsulatedTimeStamp")[0] ?? null;
    if (timestampElement && timestampElement.textContent) {
      signatureTimestamp = timestampElement.textContent.replace(/\s+/g, "");
    }
  }

  // Compute canonicalized SignatureValue element for timestamp verification
  let canonicalSignatureValue: string | undefined;
  if (signatureValueEl) {
    try {
      const canonicalizer = createTimestampCanonicalizer(signatureTimestampCanonicalizationMethod);
      canonicalSignatureValue = canonicalizer.canonicalize(signatureValueEl, new Map(), {
        inclusiveNamespacePrefixList: signatureTimestampInclusiveNamespacePrefixList,
      });
    } catch {
      // Canonicalization failed - leave undefined
    }
  }

  // Get certificate(s)
  let certificate = "";
  let certificatePEM = "";
  let certificateChain: string[] = [];
  let signerInfo = undefined;
  let publicKey = undefined;

  // The signer certificate comes from ds:KeyInfo/ds:X509Data of this signature
  const keyInfo = parts.keyInfo;
  if (keyInfo) {
    const x509Data = getDsigChildren(keyInfo, "X509Data")[0];
    if (x509Data) {
      // Get all certificates in X509Data
      const certElements = getDsigChildren(x509Data, "X509Certificate");
      if (certElements.length > 0) {
        // First cert is the signer certificate
        certificate = certElements[0].textContent?.replace(/\s+/g, "") || "";
        // Additional certs are part of the chain
        for (let i = 1; i < certElements.length; i++) {
          const chainCert = certElements[i].textContent?.replace(/\s+/g, "") || "";
          if (chainCert) {
            certificateChain.push(formatPEM(chainCert));
          }
        }
      }
    }
  }

  // Also look for XAdES CertificateValues (contains full chain excluding signer)
  const certValues = getXadesChildren(unsignedSignatureProperties, "CertificateValues")[0];
  if (certValues) {
    const encapsulatedCerts = getXadesChildren(certValues, "EncapsulatedX509Certificate");
    for (const encCert of encapsulatedCerts) {
      const chainCert = encCert.textContent?.replace(/\s+/g, "") || "";
      if (chainCert) {
        const chainPEM = formatPEM(chainCert);
        // Avoid duplicates
        if (!certificateChain.includes(chainPEM)) {
          certificateChain.push(chainPEM);
        }
      }
    }
  }

  // Extract embedded XAdES LTV revocation material (OCSP responses / CRLs) captured
  // at signing time. This lets "not revoked at signing time" be answered offline.
  let revocationValues: { ocsp: string[]; crl: string[] } | undefined;
  const revocationValuesEl = getXadesChildren(unsignedSignatureProperties, "RevocationValues")[0];
  if (revocationValuesEl) {
    const ocsp: string[] = [];
    const crl: string[] = [];
    const ocspValues = getXadesChildren(revocationValuesEl, "OCSPValues").flatMap((values) =>
      getXadesChildren(values, "EncapsulatedOCSPValue"),
    );
    const crlValues = getXadesChildren(revocationValuesEl, "CRLValues").flatMap((values) =>
      getXadesChildren(values, "EncapsulatedCRLValue"),
    );
    for (const el of ocspValues) {
      const value = el.textContent?.replace(/\s+/g, "");
      if (value) {
        ocsp.push(value);
      }
    }
    for (const el of crlValues) {
      const value = el.textContent?.replace(/\s+/g, "");
      if (value) {
        crl.push(value);
      }
    }
    if (ocsp.length > 0 || crl.length > 0) {
      revocationValues = { ocsp, crl };
    }
  }

  if (certificate) {
    certificatePEM = formatPEM(certificate);

    // Extract public key and signer info
    try {
      const x509 = new X509Certificate(certificatePEM);
      const algorithm = x509.publicKey.algorithm;

      publicKey = {
        algorithm: algorithm.name,
        ...("namedCurve" in algorithm
          ? {
              namedCurve: (algorithm as any).namedCurve as string,
            }
          : {}),
        rawData: x509.publicKey.rawData,
      };

      // Extract signer information from certificate
      signerInfo = extractSignerInfo(x509);
    } catch (error) {
      console.error("Failed to extract certificate information:", error);
    }
  }

  // Get the claimed signing time from the SignedProperties this signature
  // references. Note: this value is only authenticated once verifySignature()
  // has checked the SignedProperties digest; it is never proof of time.
  let signingTime: Date | undefined;
  const signedPropertiesReference = parts.references.find(isSignedPropertiesReference);
  const signedPropertiesUri = signedPropertiesReference?.getAttribute("URI") || "";
  if (signedPropertiesUri.startsWith("#")) {
    try {
      signingTime = readSigningTime(resolveSameDocumentReference(xmlDoc, signedPropertiesUri));
    } catch {
      // Unresolvable SignedProperties reference; reported during verification.
    }
  }

  // Get references and checksums
  const references: string[] = [];
  const signedChecksums: Record<string, string> = {};
  const digestAlgorithms: Record<string, string> = {};

  const referenceElements = parts.references;

  for (const reference of referenceElements) {
    const uri = reference.getAttribute("URI") || "";
    const type = reference.getAttribute("Type") || "";

    // Skip references that don't point to files or are SignedProperties
    if (!uri || uri.startsWith("#") || type.includes("SignedProperties")) {
      continue;
    }

    // Decode URI if needed (handle URL encoding like Sample%20File.pdf)
    let decodedUri = uri;
    try {
      decodedUri = decodeURIComponent(uri);
    } catch (e) {
      console.error(`Failed to decode URI: ${uri}`, e);
    }

    // Clean up URI
    const cleanUri = decodedUri.startsWith("./") ? decodedUri.substring(2) : decodedUri;
    references.push(cleanUri);

    // Find DigestMethod algorithm
    const digestMethodEl = getSingleDsigChild(reference, "DigestMethod");
    if (digestMethodEl) {
      const algo = digestMethodEl.getAttribute("Algorithm");
      if (algo) {
        digestAlgorithms[cleanUri] = algo;
      }
    }

    // Find DigestValue
    const digestValueEl = getSingleDsigChild(reference, "DigestValue");
    if (digestValueEl && digestValueEl.textContent) {
      if (cleanUri in signedChecksums) {
        throw new Error(`Duplicate reference to "${cleanUri}" in SignedInfo`);
      }
      signedChecksums[cleanUri] = getCompactText(digestValueEl);
    }
  }

  return {
    id: signatureId,
    signingTime: signingTime ?? new Date(),
    certificate,
    certificatePEM,
    certificateChain: certificateChain.length > 0 ? certificateChain : undefined,
    publicKey,
    signerInfo,
    signedChecksums,
    digestAlgorithms,
    references,
    algorithm: signatureAlgorithm,
    signatureValue,
    canonicalSignatureValue,
    signedInfoXml,
    canonicalizationMethod,
    signatureTimestamp,
    revocationValues,
  };
}

// This exports a testing module that won't be re-exported from the main parser
export const __test__ = {
  parseSignatureElement,
  formatPEM,
};
