import { unzipSync } from "fflate";
import { X509Certificate } from "@peculiar/x509";
import { createXMLParser, querySelector, querySelectorAll } from "../utils/xmlParser";
import { CANONICALIZATION_METHODS } from "./canonicalization/XMLCanonicalizer";
import { extractSignerInfo } from "./certificate";

import { parseSignatureFile, findSignatureFiles } from "./parser/signatureParser";
import type { EdocContainer, SignatureInfo } from "./parser/types";

export { EdocContainer, SignatureInfo };

/**
 * Options for parseEdoc. All limits apply to the sizes declared in the ZIP
 * central directory and are checked before any entry is decompressed.
 */
export interface ParseEdocOptions {
  /** Maximum number of entries in the container. Default: 1000 */
  maxEntries?: number;
  /** Maximum uncompressed size of a single entry, in bytes. Default: 100 MB */
  maxEntrySize?: number;
  /** Maximum total uncompressed size of all entries, in bytes. Default: 500 MB */
  maxTotalSize?: number;
}

/**
 * Default container limits.
 *
 * - maxEntries: signed containers normally hold a handful of documents plus a few
 *   META-INF files; 1000 leaves ample room while bounding per-entry overhead.
 * - maxEntrySize: 100 MB covers large scanned PDFs and media attachments.
 * - maxTotalSize: 500 MB keeps the fully decompressed container within what a
 *   browser tab can reasonably hold alongside the original buffer.
 *
 * Callers that need to open larger containers can raise these via ParseEdocOptions.
 */
export const DEFAULT_PARSE_EDOC_LIMITS: Readonly<Required<ParseEdocOptions>> = Object.freeze({
  maxEntries: 1000,
  maxEntrySize: 100 * 1024 * 1024,
  maxTotalSize: 500 * 1024 * 1024,
});

/**
 * DEFLATE cannot expand data by more than about 1032:1 (a 258-byte match coded in
 * two bits). A declared uncompressed size above this ratio cannot be produced by
 * the compressed data and indicates an inconsistent entry header.
 */
const MAX_DEFLATE_RATIO = 1032;

const ZIP_COMPRESSION_STORED = 0;
const ZIP_COMPRESSION_DEFLATE = 8;

function resolveLimit(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "number" || Number.isNaN(value) || value < 0) {
    throw new Error(`Invalid ${name} option: expected a non-negative number`);
  }
  return value;
}

/**
 * Parse an eDoc container from a buffer
 * @param edocBuffer The raw eDoc file content
 * @param options Optional limits for container size and entry count
 * @returns Parsed container with files, document file list, metadata file list, signed file list, and signatures
 */
export function parseEdoc(edocBuffer: Uint8Array, options: ParseEdocOptions = {}): EdocContainer {
  try {
    const maxEntries = resolveLimit(
      options.maxEntries,
      DEFAULT_PARSE_EDOC_LIMITS.maxEntries,
      "maxEntries",
    );
    const maxEntrySize = resolveLimit(
      options.maxEntrySize,
      DEFAULT_PARSE_EDOC_LIMITS.maxEntrySize,
      "maxEntrySize",
    );
    const maxTotalSize = resolveLimit(
      options.maxTotalSize,
      DEFAULT_PARSE_EDOC_LIMITS.maxTotalSize,
      "maxTotalSize",
    );

    let entryCount = 0;
    let totalSize = 0;

    // Unzip the eDoc container. The filter runs for each entry before its data is
    // allocated, so throwing here stops extraction before any oversized buffer exists.
    const unzipped = unzipSync(edocBuffer, {
      filter: (entry) => {
        entryCount++;
        if (entryCount > maxEntries) {
          throw new Error(`Container has more than ${maxEntries} entries`);
        }

        const { name, size, originalSize, compression } = entry;
        if (
          !Number.isFinite(size) ||
          !Number.isFinite(originalSize) ||
          size < 0 ||
          originalSize < 0
        ) {
          throw new Error(`Entry "${name}" has an invalid size`);
        }

        // Bytes fflate will allocate for this entry: stored entries are copied as-is,
        // deflated entries get a buffer of the declared uncompressed size.
        let allocatedSize: number;
        if (compression === ZIP_COMPRESSION_STORED) {
          allocatedSize = size;
        } else if (compression === ZIP_COMPRESSION_DEFLATE) {
          if (originalSize > size * MAX_DEFLATE_RATIO) {
            throw new Error(
              `Entry "${name}" declares an uncompressed size (${originalSize} bytes) that is inconsistent with its compressed size (${size} bytes)`,
            );
          }
          allocatedSize = originalSize;
        } else {
          throw new Error(`Entry "${name}" uses unsupported compression method ${compression}`);
        }

        if (allocatedSize > maxEntrySize) {
          throw new Error(
            `Entry "${name}" is too large (${allocatedSize} bytes, limit ${maxEntrySize})`,
          );
        }
        totalSize += allocatedSize;
        if (totalSize > maxTotalSize) {
          throw new Error(
            `Container content is too large (more than ${maxTotalSize} bytes uncompressed)`,
          );
        }
        return true;
      },
    });

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
