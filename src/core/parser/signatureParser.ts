// src/core/parser/signatureParser.ts
import { X509Certificate } from "@peculiar/x509";
import {
  createXMLParser,
  querySelector,
  querySelectorAll,
} from "../../utils/xmlParser";
import { CANONICALIZATION_METHODS } from "../canonicalization/XMLCanonicalizer";
import { extractSignerInfo } from "../certificate";
import { SignatureInfo } from "./types";
import { formatPEM } from "./certificateUtils";

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
export function parseSignatureFile(
  xmlContent: Uint8Array,
  filename: string,
): SignatureInfo | null {
  const text = new TextDecoder().decode(xmlContent);
  const parser = createXMLParser();
  const xmlDoc = parser.parseFromString(text, "application/xml");

  // Using our querySelector helper to find the signature element
  const signatureElements = querySelectorAll(
    xmlDoc,
    "ds\\:Signature, Signature",
  );

  if (signatureElements.length === 0) {
    console.warn(`No Signature elements found in ${filename}`);

    // If we have ASiC-XAdES format, try to find signatures differently
    if (text.includes("XAdESSignatures")) {
      const rootElement = xmlDoc.documentElement;

      // Try direct DOM traversal
      if (rootElement) {
        // Look for Signature elements as direct children
        const directSignature = querySelector(
          rootElement,
          "ds\\:Signature, Signature",
        );
        if (directSignature) {
          let signatureInfo = parseSignatureElement(directSignature, xmlDoc);
          signatureInfo.rawXml = text;
          return signatureInfo;
        }
      }

      // Fallback: parse as text
      const mockSignature = parseBasicSignatureFromText(text);
      if (mockSignature) {
        return {
          ...mockSignature,
          rawXml: text,
        };
      }
    }

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
export function parseSignatureElement(
  signatureElement: Element,
  xmlDoc: Document,
): SignatureInfo {
  // Get signature ID
  const signatureId = signatureElement.getAttribute("Id") || "unknown";
  // Find SignedInfo just like in browser code
  const signedInfo = querySelector(
    signatureElement,
    "ds\\:SignedInfo, SignedInfo",
  );
  if (!signedInfo) {
    throw new Error("SignedInfo element not found");
  }

  // Get the canonicalization method
  const c14nMethodEl = querySelector(
    signedInfo,
    "ds\\:CanonicalizationMethod, CanonicalizationMethod",
  );
  let canonicalizationMethod = CANONICALIZATION_METHODS.default;
  if (c14nMethodEl) {
    canonicalizationMethod =
      c14nMethodEl.getAttribute("Algorithm") || canonicalizationMethod;
  }

  // Serialize the SignedInfo element to XML string
  let signedInfoXml = "";
  try {
    // Try to use XMLSerializer if available
    if (typeof XMLSerializer !== "undefined") {
      signedInfoXml = new XMLSerializer().serializeToString(signedInfo);
    } else if (typeof window !== "undefined" && window.XMLSerializer) {
      signedInfoXml = new window.XMLSerializer().serializeToString(signedInfo);
    } else {
      // Fallback for Node.js environment
      try {
        const { JSDOM } = require("jsdom");
        const dom = new JSDOM();
        const serializer = new dom.window.XMLSerializer();
        signedInfoXml = serializer.serializeToString(signedInfo);
      } catch (e) {
        console.warn("Could not serialize SignedInfo:", e);
      }
    }
  } catch (e) {
    console.warn("Could not serialize SignedInfo element:", e);
  }

  // Get signature method
  const signatureMethod = querySelector(
    signedInfo,
    "ds\\:SignatureMethod, SignatureMethod",
  );
  const signatureAlgorithm = signatureMethod?.getAttribute("Algorithm") || "";

  // Get signature value
  const signatureValueEl = querySelector(
    signatureElement,
    "ds\\:SignatureValue, SignatureValue",
  );
  const signatureValue =
    signatureValueEl?.textContent?.replace(/\s+/g, "") || "";

  // Get certificate
  const certElement = querySelector(
    signatureElement,
    "ds\\:X509Certificate, X509Certificate",
  );
  let certificate = "";
  let certificatePEM = "";
  let signerInfo = undefined;
  let publicKey = undefined;

  if (!certElement) {
    // Try to find via KeyInfo path
    const keyInfo = querySelector(signatureElement, "ds\\:KeyInfo, KeyInfo");
    if (keyInfo) {
      const x509Data = querySelector(keyInfo, "ds\\:X509Data, X509Data");
      if (x509Data) {
        const nestedCert = querySelector(
          x509Data,
          "ds\\:X509Certificate, X509Certificate",
        );
        if (nestedCert) {
          certificate = nestedCert.textContent?.replace(/\s+/g, "") || "";
        }
      }
    }
  } else {
    certificate = certElement.textContent?.replace(/\s+/g, "") || "";
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

  // Get signing time
  const signingTimeElement = querySelector(
    xmlDoc,
    "xades\\:SigningTime, SigningTime",
  );
  const signingTime =
    signingTimeElement && signingTimeElement.textContent
      ? new Date(signingTimeElement.textContent.trim())
      : new Date();

  // Get references and checksums
  const references: string[] = [];
  const signedChecksums: Record<string, string> = {};

  const referenceElements = querySelectorAll(
    signedInfo,
    "ds\\:Reference, Reference",
  );

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
    const cleanUri = decodedUri.startsWith("./")
      ? decodedUri.substring(2)
      : decodedUri;
    references.push(cleanUri);

    // Find DigestValue
    const digestValueEl = querySelector(
      reference,
      "ds\\:DigestValue, DigestValue",
    );
    if (digestValueEl && digestValueEl.textContent) {
      signedChecksums[cleanUri] = digestValueEl.textContent.replace(/\s+/g, "");
    }
  }

  return {
    id: signatureId,
    signingTime,
    certificate,
    certificatePEM,
    publicKey,
    signerInfo,
    signedChecksums,
    references,
    algorithm: signatureAlgorithm,
    signatureValue,
    signedInfoXml,
    canonicalizationMethod,
  };
}

/**
 * Fallback for creating a basic signature from text when DOM parsing fails
 * @param xmlText The full XML text
 * @returns A basic signature or null if parsing fails
 */
export function parseBasicSignatureFromText(
  xmlText: string,
): SignatureInfo | null {
  try {
    // Extract signature ID
    const idMatch = xmlText.match(/<ds:Signature[^>]*Id=["']([^"']*)["']/);
    const id = idMatch && idMatch[1] ? idMatch[1] : "unknown";

    // Extract signature value
    const sigValueMatch = xmlText.match(
      /<ds:SignatureValue[^>]*>([\s\S]*?)<\/ds:SignatureValue>/,
    );
    const signatureValue =
      sigValueMatch && sigValueMatch[1]
        ? sigValueMatch[1].replace(/\s+/g, "")
        : "";

    // Extract certificate
    const certMatch = xmlText.match(
      /<ds:X509Certificate>([\s\S]*?)<\/ds:X509Certificate>/,
    );
    const certificate =
      certMatch && certMatch[1] ? certMatch[1].replace(/\s+/g, "") : "";

    // Extract algorithm
    const algoMatch = xmlText.match(
      /<ds:SignatureMethod[^>]*Algorithm=["']([^"']*)["']/,
    );
    const algorithm = algoMatch && algoMatch[1] ? algoMatch[1] : "";

    // Extract signing time
    const timeMatch = xmlText.match(
      /<xades:SigningTime>([\s\S]*?)<\/xades:SigningTime>/,
    );
    const signingTime =
      timeMatch && timeMatch[1] ? new Date(timeMatch[1].trim()) : new Date();

    // Extract references
    const references: string[] = [];
    const signedChecksums: Record<string, string> = {};

    // Use regex to find all references
    const refRegex =
      /<ds:Reference[^>]*URI=["']([^#][^"']*)["'][^>]*>[\s\S]*?<ds:DigestValue>([\s\S]*?)<\/ds:DigestValue>/g;
    let refMatch;

    while ((refMatch = refRegex.exec(xmlText)) !== null) {
      if (refMatch[1] && !refMatch[1].startsWith("#")) {
        const uri = decodeURIComponent(refMatch[1]);
        references.push(uri);

        if (refMatch[2]) {
          signedChecksums[uri] = refMatch[2].replace(/\s+/g, "");
        }
      }
    }

    // Format the PEM certificate
    const certificatePEM = formatPEM(certificate);

    return {
      id,
      signingTime,
      certificate,
      certificatePEM,
      signedChecksums,
      references,
      algorithm,
      signatureValue,
    };
  } catch (error) {
    console.error("Error in fallback text parsing:", error);
    return null;
  }
}

// This exports a testing module that won't be re-exported from the main parser
export const __test__ = {
  parseSignatureElement,
  parseBasicSignatureFromText,
  formatPEM,
};
