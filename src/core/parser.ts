import { unzipSync } from "fflate";
import { X509Certificate } from "@peculiar/x509";
import { createXMLParser, querySelector, querySelectorAll } from "../utils/xmlParser";
import { CANONICALIZATION_METHODS } from "./canonicalization/XMLCanonicalizer";
import { extractSignerInfo } from "./certificate";

import { parseSignatureFile, findSignatureFiles } from "./parser/signatureParser";
import type { EdocContainer, SignatureInfo } from "./parser/types";

export { EdocContainer, SignatureInfo };

/**
 * Parse an eDoc container from a buffer
 * @param edocBuffer The raw eDoc file content
 * @returns Parsed container with files, document file list, metadata file list, signed file list, and signatures
 */
export function parseEdoc(edocBuffer: Uint8Array): EdocContainer {
  try {
    // Unzip the eDoc container
    const unzipped = unzipSync(edocBuffer);

    // Convert to Maps for easier access
    const files = new Map<string, Uint8Array>();
    const documentFileList: string[] = [];
    const metadataFileList: string[] = [];

    Object.entries(unzipped).forEach(([filename, content]) => {
      files.set(filename, content);

      // Separate files into document and metadata categories
      if (filename.startsWith("META-INF/") || filename === "mimetype") {
        metadataFileList.push(filename);
      } else {
        documentFileList.push(filename);
      }
    });

    // Find and parse signatures
    const signatures: SignatureInfo[] = [];
    const signatureFiles = findSignatureFiles(files);
    const signedFileSet = new Set<string>();

    for (const sigFile of signatureFiles) {
      const sigContent = files.get(sigFile);
      if (sigContent) {
        try {
          // Parse signatures from the file - could contain multiple
          const fileSignature = parseSignatureFile(sigContent, sigFile);
          if (fileSignature) {
            signatures.push(fileSignature);
            // Add referenced files to the set of signed files
            if (fileSignature.references && fileSignature.references.length > 0) {
              fileSignature.references.forEach((ref) => {
                // Only add files that actually exist in the container
                if (files.has(ref)) {
                  signedFileSet.add(ref);
                }
              });
            }
          }
        } catch (error) {
          console.error(`Error parsing signature ${sigFile}:`, error);
        }
      }
    }
    const signedFileList = Array.from(signedFileSet);

    return {
      files,
      documentFileList,
      metadataFileList,
      signedFileList,
      signatures,
    };
  } catch (error) {
    throw new Error(
      `Failed to parse eDoc container: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
