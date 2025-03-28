import { unzipSync } from "fflate";
import { X509Certificate } from "@peculiar/x509";
import {
  createXMLParser,
  querySelector,
  querySelectorAll,
} from "../utils/xmlParser";
import { CANONICALIZATION_METHODS } from "./canonicalization/XMLCanonicalizer";
import { extractSignerInfo } from "./certificate";

import {
  parseSignatureFile,
  findSignatureFiles,
} from "./parser/signatureParser";
import type { EdocContainer, SignatureInfo } from "./parser/types";

export { EdocContainer, SignatureInfo };

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

    for (const sigFile of signatureFiles) {
      const sigContent = files.get(sigFile);
      if (sigContent) {
        try {
          // Parse signatures from the file - could contain multiple
          const fileSignature = parseSignatureFile(sigContent, sigFile);
          if (fileSignature) {
            signatures.push(fileSignature);
          }
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
