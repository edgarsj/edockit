/**
 * Recursive DOM traversal to find elements with a given tag name
 * (Fallback method when XPath is not available or fails)
 *
 * @param parent The parent element to search within
 * @param selector CSS-like selector with namespace support (e.g., "ds:SignedInfo, SignedInfo")
 * @returns Array of matching elements
 */
export function findElementsByTagNameRecursive(parent: Node, selector: string): Element[] {
  const results: Element[] = [];
  const selectors = selector.split(",").map((s) => s.trim());

  // Parse each selector part to extract namespace and local name
  const parsedSelectors: Array<{ ns?: string; name: string }> = [];
  for (const sel of selectors) {
    const parts = sel.split(/\\:|:/).filter(Boolean);
    if (parts.length === 1) {
      parsedSelectors.push({ name: parts[0] });
    } else if (parts.length === 2) {
      parsedSelectors.push({ ns: parts[0], name: parts[1] });
    }
  }

  // Recursive search function - keep the original node references
  function searchNode(node: Node) {
    if (!node) return;

    if (node.nodeType === 1) {
      // Element node - make sure we're working with an actual DOM Element
      const element = node as Element;
      const nodeName = element.nodeName;
      const localName = element.localName;

      // Check if this element matches any of our selectors
      for (const sel of parsedSelectors) {
        // Match by full nodeName (which might include namespace prefix)
        if (sel.ns && nodeName === `${sel.ns}:${sel.name}`) {
          results.push(element); // Store the actual DOM element reference
          break;
        }
        // Match by local name only
        if (localName === sel.name || nodeName === sel.name) {
          results.push(element); // Store the actual DOM element reference
          break;
        }
        // Match by checking if nodeName ends with the local name
        if (nodeName.endsWith(`:${sel.name}`)) {
          results.push(element); // Store the actual DOM element reference
          break;
        }
      }
    }

    // Search all child nodes
    if (node.childNodes) {
      for (let i = 0; i < node.childNodes.length; i++) {
        searchNode(node.childNodes[i]);
      }
    }
  }

  searchNode(parent);
  return results;
}

/**
 * A cross-environment XML parser that works in both Node.js and browsers
 * with enhanced XPath support for handling namespaced elements
 */

// Type definitions
export interface XMLParserInterface {
  parseFromString(text: string, mimeType: string): Document;
}

export type NamespaceMap = Record<string, string>;

// Known XML namespaces used in XML Signatures and related standards
export const NAMESPACES: NamespaceMap = {
  ds: "http://www.w3.org/2000/09/xmldsig#",
  dsig11: "http://www.w3.org/2009/xmldsig11#",
  dsig2: "http://www.w3.org/2010/xmldsig2#",
  ec: "http://www.w3.org/2001/10/xml-exc-c14n#",
  dsig_more: "http://www.w3.org/2001/04/xmldsig-more#",
  xenc: "http://www.w3.org/2001/04/xmlenc#",
  xenc11: "http://www.w3.org/2009/xmlenc11#",
  xades: "http://uri.etsi.org/01903/v1.3.2#",
  xades141: "http://uri.etsi.org/01903/v1.4.1#",
  asic: "http://uri.etsi.org/02918/v1.2.1#",
};

/**
 * Create an XML parser that works in both browser and Node environments
 */
export function createXMLParser(): XMLParserInterface {
  // Check if we're in a browser environment with native DOM support
  if (typeof window !== "undefined" && window.DOMParser) {
    return new window.DOMParser();
  }

  // We're in Node.js, so use xmldom
  try {
    // Import dynamically to avoid bundling issues
    const { DOMParser } = require("@xmldom/xmldom");
    return new DOMParser();
  } catch (e) {
    throw new Error(
      "XML DOM parser not available. In Node.js environments, please install @xmldom/xmldom package.",
    );
  }
}

/**
 * Uses XPath to find a single element in an XML document
 *
 * @param parent The parent element or document to search within
 * @param xpathExpression The XPath expression to evaluate
 * @param namespaces Optional namespace mapping (defaults to common XML signature namespaces)
 * @returns The found element or null
 */
export function queryByXPath(
  parent: Document | Element,
  xpathExpression: string,
  namespaces: NamespaceMap = NAMESPACES,
): Element | null {
  try {
    // Browser environment with native XPath
    if (typeof document !== "undefined" && document.evaluate) {
      const nsResolver = createNsResolverForBrowser(namespaces);
      const result = document.evaluate(
        xpathExpression,
        parent,
        nsResolver,
        XPathResult.FIRST_ORDERED_NODE_TYPE,
        null,
      );
      return result.singleNodeValue as Element;
    }
    // Node.js environment with xpath module
    else {
      const xpath = require("xpath");
      const nsResolver = createNsResolverForNode(namespaces);

      // Use a try-catch here to handle specific XPath issues
      try {
        const nodes = xpath.select(xpathExpression, parent, nsResolver);
        return nodes.length > 0 ? nodes[0] : null;
      } catch (err: unknown) {
        // If we get a namespace error, try a simpler XPath with just local-name()
        if (
          typeof err === "object" &&
          err !== null &&
          "message" in err &&
          typeof err.message === "string" &&
          err.message.includes("Cannot resolve QName")
        ) {
          // Extract the element name we're looking for from the XPath
          const match = xpathExpression.match(/local-name\(\)='([^']+)'/);
          if (match && match[1]) {
            const elementName = match[1];
            const simplifiedXPath = `.//*[local-name()='${elementName}']`;
            const nodes = xpath.select(simplifiedXPath, parent);
            return nodes.length > 0 ? nodes[0] : null;
          }
        }
        throw err; // Re-throw if we couldn't handle it
      }
    }
  } catch (e) {
    console.error(`XPath evaluation failed for "${xpathExpression}":`, e);
    return null;
  }
}

/**
 * Uses XPath to find all matching elements in an XML document
 *
 * @param parent The parent element or document to search within
 * @param xpathExpression The XPath expression to evaluate
 * @param namespaces Optional namespace mapping (defaults to common XML signature namespaces)
 * @returns Array of matching elements
 */
export function queryAllByXPath(
  parent: Document | Element,
  xpathExpression: string,
  namespaces: NamespaceMap = NAMESPACES,
): Element[] {
  try {
    // Browser environment with native XPath
    if (typeof document !== "undefined" && document.evaluate) {
      const nsResolver = createNsResolverForBrowser(namespaces);
      const result = document.evaluate(
        xpathExpression,
        parent,
        nsResolver,
        XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
        null,
      );

      const elements: Element[] = [];
      for (let i = 0; i < result.snapshotLength; i++) {
        elements.push(result.snapshotItem(i) as Element);
      }
      return elements;
    }
    // Node.js environment with xpath module
    else {
      const xpath = require("xpath");
      const nsResolver = createNsResolverForNode(namespaces);

      // Use a try-catch here to handle specific XPath issues
      try {
        const nodes = xpath.select(xpathExpression, parent, nsResolver);
        return nodes as Element[];
      } catch (err: unknown) {
        // If we get a namespace error, try a simpler XPath with just local-name()
        if (
          typeof err === "object" &&
          err !== null &&
          "message" in err &&
          typeof err.message === "string" &&
          err.message.includes("Cannot resolve QName")
        ) {
          // Extract the element name we're looking for from the XPath
          const match = xpathExpression.match(/local-name\(\)='([^']+)'/);
          if (match && match[1]) {
            const elementName = match[1];
            const simplifiedXPath = `.//*[local-name()='${elementName}']`;
            const nodes = xpath.select(simplifiedXPath, parent);
            return nodes as Element[];
          }
        }
        throw err; // Re-throw if we couldn't handle it
      }
    }
  } catch (e) {
    console.error(`XPath evaluation failed for "${xpathExpression}":`, e);
    return [];
  }
}

/**
 * Helper function to create a namespace resolver for browser environments
 */
function createNsResolverForBrowser(namespaces: NamespaceMap): XPathNSResolver {
  return function (prefix: string | null): string | null {
    if (prefix === null) return null;
    return namespaces[prefix] || null;
  };
}

/**
 * Helper function to create a namespace resolver for Node.js environments
 */
function createNsResolverForNode(namespaces: NamespaceMap): any {
  return namespaces;
}

/**
 * Converts a CSS-like selector (with namespace support) to an XPath expression
 *
 * @param selector CSS-like selector (e.g., "ds:SignedInfo, SignedInfo")
 * @returns Equivalent XPath expression
 */
export function selectorToXPath(selector: string): string {
  // Split by comma to handle alternative selectors
  const parts = selector.split(",").map((s) => s.trim());
  const xpathParts: string[] = [];

  for (const part of parts) {
    // Handle namespaced selectors (both prefix:name and prefix\\:name formats)
    const segments = part.split(/\\:|:/).filter(Boolean);

    if (segments.length === 1) {
      // Simple element name without namespace
      // Match any element with the right local name
      xpathParts.push(`.//*[local-name()='${segments[0]}']`);
    } else if (segments.length === 2) {
      // Element with namespace prefix - only use local-name() or specific namespace prefix
      // that we know is registered, avoiding the generic 'ns:' prefix
      xpathParts.push(`.//${segments[0]}:${segments[1]} | .//*[local-name()='${segments[1]}']`);
    }
  }

  // Join with | operator (XPath's OR)
  return xpathParts.join(" | ");
}

/**
 * Enhanced querySelector that uses XPath for better namespace handling
 * (Drop-in replacement for the original querySelector function)
 *
 * @param parent The parent element or document to search within
 * @param selector A CSS-like selector (with namespace handling)
 * @returns The found element or null
 */
export function querySelector(parent: Document | Element, selector: string): Element | null {
  // First try native querySelector if we're in a browser
  if (typeof parent.querySelector === "function") {
    try {
      const result = parent.querySelector(selector);
      if (result) return result;
    } catch (e) {
      // Fallback to XPath if querySelector fails (e.g., due to namespace issues)
    }
  }

  // First try with our enhanced DOM traversal methods (more reliable in some cases)
  const elements = findElementsByTagNameRecursive(parent, selector);
  if (elements.length > 0) {
    return elements[0];
  }

  // Then try XPath as a fallback
  try {
    const xpath = selectorToXPath(selector);
    return queryByXPath(parent, xpath);
  } catch (e) {
    console.warn("XPath query failed, using direct DOM traversal as fallback");
    return null;
  }
}

/**
 * Enhanced querySelectorAll that uses XPath for better namespace handling
 * (Drop-in replacement for the original querySelectorAll function)
 *
 * @param parent The parent element or document to search within
 * @param selector A CSS-like selector (with namespace handling)
 * @returns Array of matching elements
 */
export function querySelectorAll(parent: Document | Element, selector: string): Element[] {
  // First try native querySelectorAll if we're in a browser
  if (typeof parent.querySelectorAll === "function") {
    try {
      const results = parent.querySelectorAll(selector);
      if (results.length > 0) {
        const elements: Element[] = [];
        for (let i = 0; i < results.length; i++) {
          elements.push(results[i] as Element);
        }
        return elements;
      }
    } catch (e) {
      // Fallback to XPath if querySelectorAll fails (e.g., due to namespace issues)
    }
  }

  // First try with our enhanced DOM traversal methods (more reliable in some cases)
  const elements = findElementsByTagNameRecursive(parent, selector);
  if (elements.length > 0) {
    return elements;
  }

  // Then try XPath as a fallback
  try {
    const xpath = selectorToXPath(selector);
    return queryAllByXPath(parent, xpath);
  } catch (e) {
    console.warn("XPath query failed, using direct DOM traversal as fallback");
    return [];
  }
}

/**
 * Serialize a DOM node to XML string
 */
export function serializeToXML(node: Node): string {
  // Check if we're in a browser environment with native XMLSerializer
  if (typeof window !== "undefined" && window.XMLSerializer) {
    return new window.XMLSerializer().serializeToString(node);
  }

  // If we're using xmldom
  try {
    const { XMLSerializer } = require("@xmldom/xmldom");
    return new XMLSerializer().serializeToString(node);
  } catch (e) {
    throw new Error(
      "XML Serializer not available. In Node.js environments, please install @xmldom/xmldom package.",
    );
  }
}

/**
 * Debug function to print XML structure for troubleshooting
 * @param node The root node to debug
 * @param depth Current depth (used for indentation)
 */
export function debugXmlStructure(node: Node, depth = 0): void {
  if (!node) return;

  const indent = "  ".repeat(depth);

  if (node.nodeType === 1) {
    // ELEMENT_NODE
    const element = node as Element;
    console.log(`${indent}Element: ${node.nodeName}`);
    console.log(`${indent}  localName: ${element.localName || "undefined"}`);
    console.log(`${indent}  namespaceURI: ${element.namespaceURI || "undefined"}`);

    if (element.attributes) {
      console.log(`${indent}  attributes:`);
      for (let i = 0; i < element.attributes.length; i++) {
        const attr = element.attributes[i];
        console.log(`${indent}    ${attr.name}: ${attr.value}`);
      }
    }

    if (node.childNodes) {
      for (let i = 0; i < node.childNodes.length; i++) {
        debugXmlStructure(node.childNodes[i], depth + 1);
      }
    }
  } else if (node.nodeType === 3) {
    // TEXT_NODE
    const text = node.nodeValue?.trim();
    if (text) {
      console.log(`${indent}Text: "${text}"`);
    }
  }
}
