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
  if (typeof window !== "undefined" && window.DOMParser) {
    console.log("Using native DOMParser");
    return new window.DOMParser();
  }

  // We're in Node.js, so use jsdom
  try {
    // Import dynamically to avoid bundling issues
    const { JSDOM } = require("jsdom");
    return {
      parseFromString(text: string, mimeType: string): Document {
        const dom = new JSDOM(text, { contentType: mimeType });
        console.log("Using jsdom");
        return dom.window.document;
      },
    };
  } catch (e) {
    throw new Error(
      "XML DOM parser not available. In Node.js environments, please install jsdom package.",
    );
  }
}

/**
 * Helper function to find elements using a jQuery-like selector syntax
 * @param parent The parent element or document to search within
 * @param selector A CSS-like selector (with namespace handling)
 * @returns The found element or null
 */
export function querySelector(parent: Document | Element, selector: string): Element | null {
  // First check if the environment supports querySelector natively
  if (typeof parent.querySelector === "function") {
    try {
      return parent.querySelector(selector);
    } catch (e) {
      // If it fails (e.g. due to namespace issues), continue with our custom implementation
    }
  }

  // Split on comma for alternative selectors
  const selectors = selector.split(",").map((s) => s.trim());

  for (const sel of selectors) {
    // Handle namespaced selectors (both ds:TagName and ds\\:TagName formats)
    const parts = sel.split(/\\:|:/).filter(Boolean);
    const localName = parts.length > 1 ? parts[1] : parts[0];

    // Try to find the element by local name
    if ("getElementsByTagName" in parent) {
      const elements = parent.getElementsByTagName(localName);
      if (elements.length > 0) {
        return elements[0] as Element;
      }
    }

    // If we're in a Document, try with namespace for better coverage
    if ("getElementsByTagNameNS" in parent) {
      // Check if we're dealing with a Document
      const isDocument = (parent as any).nodeType === 9; // 9 is DOCUMENT_NODE
      if (isDocument) {
        try {
          // Try with wildcard namespace
          const nsElements = (parent as Document).getElementsByTagNameNS("*", localName);
          if (nsElements.length > 0) {
            return nsElements[0] as Element;
          }
        } catch (e) {
          // Some DOM implementations might not support this
        }
      }
    }
  }

  return null;
}

/**
 * Helper function to find all elements using a jQuery-like selector syntax
 * @param parent The parent element or document to search within
 * @param selector A CSS-like selector (with namespace handling)
 * @returns Array of matching elements
 */
export function querySelectorAll(parent: Document | Element, selector: string): Element[] {
  const results: Element[] = [];

  // First check if the environment supports querySelectorAll natively
  if (typeof parent.querySelectorAll === "function") {
    try {
      const elements = parent.querySelectorAll(selector);
      for (let i = 0; i < elements.length; i++) {
        results.push(elements[i] as Element);
      }
      if (results.length > 0) {
        return results;
      }
    } catch (e) {
      // If it fails, continue with our custom implementation
    }
  }

  // Split on comma for alternative selectors
  const selectors = selector.split(",").map((s) => s.trim());

  for (const sel of selectors) {
    // Handle namespaced selectors
    const parts = sel.split(/\\:|:/).filter(Boolean);
    const localName = parts.length > 1 ? parts[1] : parts[0];

    // Try to find elements by local name
    if ("getElementsByTagName" in parent) {
      const elements = parent.getElementsByTagName(localName);
      for (let i = 0; i < elements.length; i++) {
        results.push(elements[i] as Element);
      }
    }

    // If we're in a Document, try with namespace
    if ("getElementsByTagNameNS" in parent) {
      // Check if we're dealing with a Document
      const isDocument = (parent as any).nodeType === 9; // 9 is DOCUMENT_NODE
      if (isDocument) {
        try {
          // Try with wildcard namespace
          const nsElements = (parent as Document).getElementsByTagNameNS("*", localName);
          for (let i = 0; i < nsElements.length; i++) {
            if (!results.includes(nsElements[i] as Element)) {
              results.push(nsElements[i] as Element);
            }
          }
        } catch (e) {
          // Some DOM implementations might not support this
        }
      }
    }
  }

  return results;
}

/**
 * Serialize a DOM node to XML string
 */
export function serializeToXML(node: Node): string {
  // Check if we're in a browser environment with native XMLSerializer
  if (typeof window !== "undefined" && window.XMLSerializer) {
    return new window.XMLSerializer().serializeToString(node);
  }

  // If we're using jsdom
  try {
    const { JSDOM } = require("jsdom");
    const { document } = new JSDOM().window;
    const serializer = new document.defaultView.XMLSerializer();
    return serializer.serializeToString(node);
  } catch (e) {
    throw new Error(
      "XML Serializer not available. In Node.js environments, please install jsdom package.",
    );
  }
}
