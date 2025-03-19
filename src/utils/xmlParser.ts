/**
 * A cross-environment XML parser that works in both Node.js and browsers
 */

// Type for DOM parser interface we need
export interface XMLParserInterface {
  parseFromString(text: string, mimeType: string): Document;
}

/**
 * Create an XML parser that works in both browser and Node environments
 */
export function createXMLParser(): XMLParserInterface {
  // Check if we're in a browser environment with native DOM support
  if (typeof window !== 'undefined' && window.DOMParser) {
    return new window.DOMParser();
  } 
  
  // We're in Node.js, so use xmldom
  try {
    // Import dynamically to avoid bundling issues
    const { DOMParser } = require('@xmldom/xmldom');
    return new DOMParser();
  } catch (error) {
    throw new Error(
      'XML DOM parser not available. In Node.js environments, please install @xmldom/xmldom package.'
    );
  }
}

/**
 * Serialize a DOM node to XML string
 */
export function serializeToXML(node: Node): string {
  // Check if we're in a browser environment with native XMLSerializer
  if (typeof window !== 'undefined' && window.XMLSerializer) {
    return new window.XMLSerializer().serializeToString(node);
  }

  // We're in Node.js, so use xmldom
  try {
    const { XMLSerializer } = require('@xmldom/xmldom');
    return new XMLSerializer().serializeToString(node);
  } catch (error) {
    throw new Error(
      'XML Serializer not available. In Node.js environments, please install @xmldom/xmldom package.'
    );
  }
}
