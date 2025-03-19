import { unzipSync } from "fflate";
import { X509Certificate } from "@peculiar/x509";
import {
  createXMLParser,
  querySelector,
  querySelectorAll,
} from "../utils/xmlParser";
import { extractSignerInfo } from "./certificate";

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
}

/**
 * Parse an eDoc container from a buffer
 * @param edocBuffer The raw eDoc file content
 * @returns Parsed container with files and signatures
 */
export function parseEdoc(edocBuffer: Uint8Array): EdocContainer {
  try {
    // Unzip the eDoc container
    const unzipped = unzipSync(edocBuffer);

    // Convert to a Map for easier access
    const files = new Map<string, Uint8Array>();
    Object.entries(unzipped).forEach(([filename, content]) => {
      files.set(filename, content);
    });

    // Find and parse signatures
    const signatures: SignatureInfo[] = [];
    const signatureFiles = findSignatureFiles(files);
    console.log(
      `Found ${signatureFiles.length} signature files: {${signatureFiles.join(", ")}}`,
    );

    for (const sigFile of signatureFiles) {
      const sigContent = files.get(sigFile);
      if (sigContent) {
        try {
          // Parse signatures from the file - could contain multiple
          const fileSignatures = parseSignatureFile(sigContent, sigFile);
          signatures.push(...fileSignatures);
          console.log(
            `Found ${fileSignatures.length} signatures in ${sigFile}`,
          );
        } catch (error) {
          console.error(`Error parsing signature ${sigFile}:`, error);
        }
      }
    }

    return {
      files,
      signatures,
    };
  } catch (error) {
    throw new Error(
      `Failed to parse eDoc container: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Parse a signature file that may contain multiple signatures
 * @param xmlContent The XML file content
 * @param filename The filename (for reference)
 * @returns Array of parsed signatures
 */
function parseSignatureFile(
  xmlContent: Uint8Array,
  filename: string,
): SignatureInfo[] {
  const text = new TextDecoder().decode(xmlContent);
  const parser = createXMLParser();
  const xmlDoc = parser.parseFromString(text, "application/xml");

  // Using our querySelector helper to find signatures (similar to browser code)
  const signatureElements = querySelectorAll(
    xmlDoc,
    "ds\\:Signature, Signature",
  );

  if (signatureElements.length === 0) {
    console.warn(`No Signature elements found in ${filename}`);

    // If we have ASiC-XAdES format, try to find signatures differently
    if (text.includes("XAdESSignatures")) {
      const rootElement = xmlDoc.documentElement;
      console.log(`Root element is: ${rootElement?.nodeName}`);

      // Try direct DOM traversal
      if (rootElement) {
        // Look for Signature elements as direct children
        const directSignatures = querySelectorAll(
          rootElement,
          "ds\\:Signature, Signature",
        );
        if (directSignatures.length > 0) {
          console.log(
            `Found ${directSignatures.length} signature elements by direct traversal`,
          );
          return directSignatures.map((sig) =>
            parseSignatureElement(sig, xmlDoc),
          );
        }
      }

      // Fallback: parse as text
      console.log("Attempting fallback text parsing");
      const mockSignature = parseBasicSignatureFromText(text);
      if (mockSignature) {
        return [mockSignature];
      }
    }

    return [];
  }

  console.log(
    `Found ${signatureElements.length} signature elements, parsing...`,
  );

  // Parse each signature
  return signatureElements.map((sig) => parseSignatureElement(sig, xmlDoc));
}
/**
 * Find signature files in the eDoc container
 * @param files Map of filenames to file contents
 * @returns Array of signature filenames
 */
function findSignatureFiles(files: Map<string, Uint8Array>): string[] {
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
 * Format a certificate string as a proper PEM certificate
 * @param certBase64 Base64-encoded certificate
 * @returns Formatted PEM certificate
 */
function formatPEM(certBase64?: string): string {
  if (!certBase64) return "";

  // Remove any whitespace from the base64 string
  const cleanBase64 = certBase64.replace(/\s+/g, "");

  // Split the base64 into lines of 64 characters
  const lines = [];
  for (let i = 0; i < cleanBase64.length; i += 64) {
    lines.push(cleanBase64.substring(i, i + 64));
  }

  // Format as PEM certificate
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Parse a single signature element using a browser-like approach
 * @param signatureElement The signature element to parse
 * @param xmlDoc The parent XML document
 * @returns Parsed signature information
 */
function parseSignatureElement(
  signatureElement: Element,
  xmlDoc: Document,
): SignatureInfo {
  console.log(`Parsing signature element: ${signatureElement.nodeName}`);

  // Get signature ID
  const signatureId = signatureElement.getAttribute("Id") || "unknown";
  console.log(`Signature ID: ${signatureId}`);

  // Find SignedInfo just like in browser code
  const signedInfo = querySelector(
    signatureElement,
    "ds\\:SignedInfo, SignedInfo",
  );
  if (!signedInfo) {
    throw new Error("SignedInfo element not found");
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
  };
}

/**
 * Fallback for creating a basic signature from text when DOM parsing fails
 * @param xmlText The full XML text
 * @returns A basic signature or null if parsing fails
 */
function parseBasicSignatureFromText(xmlText: string): SignatureInfo | null {
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
