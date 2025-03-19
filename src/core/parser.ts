import { unzipSync } from 'fflate';
import { createXMLParser } from '../utils/xmlParser';

// Types for the parsed eDoc container
export interface EdocContainer {
  files: Map<string, Uint8Array>;
  signatures: SignatureInfo[];
}

export interface SignatureInfo {
  id: string;
  signingTime: Date;
  certificate: string;
  signedChecksums: Record<string, string>;
  signerInfo?: {
    commonName?: string;
    organization?: string;
    country?: string;
  };
  references: string[]; // Filenames referenced by this signature
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
    
    for (const sigFile of signatureFiles) {
      const sigContent = files.get(sigFile);
      if (sigContent) {
        const sigInfo = parseSignature(sigContent);
        signatures.push(sigInfo);
      }
    }
    
    return {
      files,
      signatures
    };
  } catch (error) {
    throw new Error(`Failed to parse eDoc container: ${error instanceof Error ? error.message : String(error)}`);
  }
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
  return Array.from(files.keys()).filter(filename => 
    filename.match(/signatures\d*\.xml$/) || 
    filename.match(/META-INF\/signatures.*\.xml$/)
  );
}

/**
 * Parse a signature XML file
 * @param xmlContent The XML signature content
 * @returns Parsed signature information
 */
export function parseSignature(xmlContent: Uint8Array): SignatureInfo {
  const text = new TextDecoder().decode(xmlContent);
  const parser = createXMLParser();
  const xmlDoc = parser.parseFromString(text, 'application/xml');
  
  // Extract signature ID
  const signatureElement = xmlDoc.getElementsByTagName('Signature')[0];
  const signatureId = signatureElement?.getAttribute('Id') || 'unknown';
  
  // Extract signing time 
  const signingTimeElement = xmlDoc.getElementsByTagName('SigningTime')[0];
  const signingTime = signingTimeElement 
    ? new Date(signingTimeElement.textContent || '') 
    : new Date();
  
  // Extract certificate
  const certificateElement = xmlDoc.getElementsByTagName('X509Certificate')[0];
  const certificate = certificateElement?.textContent || '';
  
  // Extract references and checksums
  const references: string[] = [];
  const signedChecksums: Record<string, string> = {};
  
  const referenceElements = xmlDoc.getElementsByTagName('Reference');
  for (let i = 0; i < referenceElements.length; i++) {
    const reference = referenceElements[i];
    const uri = reference.getAttribute('URI') || '';
    
    // Skip signature references that don't point to files
    if (!uri || uri.startsWith('#')) continue;
    
    references.push(uri);
    
    // Extract digest value (checksum)
    const digestValueElement = reference.getElementsByTagName('DigestValue')[0];
    if (digestValueElement && digestValueElement.textContent) {
      signedChecksums[uri] = digestValueElement.textContent;
    }
  }
  
  // TODO: Extract signer info from certificate in certificate.ts
  
  return {
    id: signatureId,
    signingTime,
    certificate,
    signedChecksums,
    references
  };
}
