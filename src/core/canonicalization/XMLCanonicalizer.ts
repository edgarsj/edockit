// Define types for canonicalization methods
interface CanonMethod {
  beforeChildren: (hasElementChildren?: boolean, hasMixedContent?: boolean) => string;
  afterChildren: (hasElementChildren?: boolean, hasMixedContent?: boolean) => string;
  betweenChildren: (
    prevIsElement?: boolean,
    nextIsElement?: boolean,
    hasMixedContent?: boolean,
  ) => string;
  afterElement: () => string;
  isCanonicalizationMethod?: string; // ID of canonicalization method for specific handling
}

// Canonicalization method URIs
const CANONICALIZATION_METHODS = {
  default: "c14n",
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": "c14n",
  "http://www.w3.org/2006/12/xml-c14n11": "c14n11",
  "http://www.w3.org/2001/10/xml-exc-c14n#": "c14n_exc",
};

// Internal method implementations
const methods: Record<string, CanonMethod> = {
  c14n: {
    beforeChildren: () => "",
    afterChildren: () => "",
    betweenChildren: () => "",
    afterElement: () => "",
    isCanonicalizationMethod: "c14n",
  },
  c14n11: {
    beforeChildren: (hasElementChildren?: boolean, hasMixedContent?: boolean) => {
      // If it's mixed content, don't add newlines
      if (hasMixedContent) return "";
      return hasElementChildren ? "\n" : "";
    },
    afterChildren: (hasElementChildren?: boolean, hasMixedContent?: boolean) => {
      // If it's mixed content, don't add newlines
      if (hasMixedContent) return "";
      return hasElementChildren ? "\n" : "";
    },
    betweenChildren: (
      prevIsElement?: boolean,
      nextIsElement?: boolean,
      hasMixedContent?: boolean,
    ) => {
      // If it's mixed content, don't add newlines between elements
      if (hasMixedContent) return "";
      // Only add newline between elements
      return prevIsElement && nextIsElement ? "\n" : "";
    },
    afterElement: () => "",
    isCanonicalizationMethod: "c14n11",
  },
  c14n_exc: {
    // Placeholder for exclusive canonicalization - to be implemented
    beforeChildren: () => {
      return "";
    },
    afterChildren: () => {
      return "";
    },
    betweenChildren: () => {
      return "";
    },
    afterElement: () => {
      return "";
    },
    isCanonicalizationMethod: "c14n_exc",
  },
};

// Define types for DOM elements since we're using TypeScript
interface Node {
  nodeType: number;
  nodeName: string;
  localName?: string;
  prefix?: string;
  parentNode?: Node;
  attributes?: NamedNodeMap;
  childNodes: NodeListOf<Node>;
  nodeValue: string | null;
}

interface NamedNodeMap {
  length: number;
  [index: number]: Attr;
  item(index: number): Attr | null;
}

interface Attr {
  name: string;
  value: string;
}

interface NodeListOf<T> {
  length: number;
  item(index: number): T | null;
  [index: number]: T;
}

// Define these constants as they're used in the code
const NODE_TYPES = {
  ELEMENT_NODE: 1,
  TEXT_NODE: 3,
};

// Whitespace information to track
interface WhitespaceInfo {
  hasMixedContent?: boolean; // Whether element has both elements and text
  hasExistingLinebreaks?: boolean; // Whether element already has linebreaks
  originalContent?: Record<string, any>; // Original content and whitespace info
}

// Extend the Node interface to include whitespace information
interface NodeWithWhitespace extends Node {
  _whitespace?: WhitespaceInfo;
  _originalText?: string; // To store original text content
}

class XMLCanonicalizer {
  private method: CanonMethod;

  constructor(method: CanonMethod = methods.c14n) {
    this.method = method;
  }

  // Static method to get canonicalizer by URI
  static fromMethod(methodUri: string): XMLCanonicalizer {
    const methodKey = CANONICALIZATION_METHODS[methodUri as keyof typeof CANONICALIZATION_METHODS];
    if (!methodKey) {
      throw new Error(`Unsupported canonicalization method: ${methodUri}`);
    }
    return new XMLCanonicalizer(methods[methodKey]);
  }

  static base64Elements = new Set([
    "DigestValue",
    "X509Certificate",
    "EncapsulatedTimeStamp",
    "EncapsulatedOCSPValue",
    "IssuerSerialV2",
  ]);

  setMethod(method: CanonMethod): void {
    this.method = method;
  }

  static escapeXml(text: string): string {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&apos;");
  }

  static collectNamespaces(
    node: Node,
    visibleNamespaces = new Map<string, string>(),
  ): Map<string, string> {
    let current: Node | undefined = node;
    while (current && current.nodeType === NODE_TYPES.ELEMENT_NODE) {
      if (current.attributes) {
        Array.from(current.attributes).forEach((attr) => {
          if (attr.name === "xmlns") {
            visibleNamespaces.set("", attr.value);
          } else if (attr.name.startsWith("xmlns:")) {
            const prefix = attr.name.substring(6);
            if (!visibleNamespaces.has(prefix)) {
              visibleNamespaces.set(prefix, attr.value);
            }
          }
        });
      }
      current = current.parentNode;
    }
    return visibleNamespaces;
  }

  static isBase64Element(node: Node): boolean {
    return (
      node.nodeType === NODE_TYPES.ELEMENT_NODE &&
      node.localName !== undefined &&
      this.base64Elements.has(node.localName)
    );
  }

  // Method to analyze whitespace in document
  static analyzeWhitespace(node: Node): void {
    // If node is a document, use the document element
    const rootNode =
      node.nodeType === NODE_TYPES.ELEMENT_NODE ? node : (node as Document).documentElement;

    function analyzeNode(node: NodeWithWhitespace): void {
      if (node.nodeType === NODE_TYPES.ELEMENT_NODE) {
        // Initialize whitespace info
        node._whitespace = {
          hasMixedContent: false,
          hasExistingLinebreaks: false,
          originalContent: {},
        };

        const children = Array.from(node.childNodes);
        let hasTextContent = false;
        let hasElementContent = false;
        let hasLinebreaks = false;

        // First, check if there's any non-whitespace text content
        for (const child of children) {
          if (child.nodeType === NODE_TYPES.TEXT_NODE) {
            const text = child.nodeValue || "";
            if (text.trim().length > 0) {
              hasTextContent = true;
              break;
            }
          }
        }

        // Second, check if there are any element children
        for (const child of children) {
          if (child.nodeType === NODE_TYPES.ELEMENT_NODE) {
            hasElementContent = true;
            break;
          }
        }

        // Now process all children and analyze recursively
        for (let i = 0; i < children.length; i++) {
          const child = children[i];

          if (child.nodeType === NODE_TYPES.TEXT_NODE) {
            const text = child.nodeValue || "";

            // Store original text
            (child as NodeWithWhitespace)._originalText = text;

            // Check for linebreaks in text
            if (text.includes("\n")) {
              hasLinebreaks = true;
            }
          } else if (child.nodeType === NODE_TYPES.ELEMENT_NODE) {
            // Recursively analyze child elements
            analyzeNode(child as NodeWithWhitespace);
          }
        }

        // Set mixed content flag - true if there's both text content and element children
        node._whitespace.hasMixedContent = hasTextContent && hasElementContent;
        node._whitespace.hasExistingLinebreaks = hasLinebreaks;
      }
    }

    analyzeNode(rootNode as NodeWithWhitespace);
  }

  canonicalize(
    node: NodeWithWhitespace,
    visibleNamespaces = new Map<string, string>(),
    options = { isStartingNode: true },
  ): string {
    if (!node) return "";

    let result = "";

    if (node.nodeType === NODE_TYPES.ELEMENT_NODE) {
      // Create a new map for this element's visible namespaces
      const elementVisibleNamespaces = new Map(visibleNamespaces);

      // Collect namespaces declared on this element
      if (node.attributes) {
        Array.from(node.attributes).forEach((attr) => {
          if (attr.name === "xmlns") {
            elementVisibleNamespaces.set("", attr.value);
          } else if (attr.name.startsWith("xmlns:")) {
            const prefix = attr.name.substring(6);
            elementVisibleNamespaces.set(prefix, attr.value);
          }
        });
      }

      // Prepare the element's start tag
      const prefix = node.prefix || "";
      const localName = node.localName || node.nodeName.split(":").pop() || "";
      const qName = prefix ? `${prefix}:${localName}` : localName;

      result += "<" + qName;

      // Handle namespaces based on whether it's the starting node
      if (options.isStartingNode) {
        // Collect all namespaces in scope for this element
        const allNamespaces = XMLCanonicalizer.collectNamespaces(node);

        // Include all namespaces that are in scope, sorted appropriately
        const nsEntries = Array.from(allNamespaces.entries()).sort((a, b) => {
          if (a[0] === "") return -1;
          if (b[0] === "") return 1;
          return a[0].localeCompare(b[0]);
        });

        for (const [prefix, uri] of nsEntries) {
          if (prefix === "") {
            result += ` xmlns="${uri}"`;
          } else {
            result += ` xmlns:${prefix}="${uri}"`;
          }
        }
      } else {
        // For non-starting nodes, only include newly declared namespaces
        const nsEntries = Array.from(elementVisibleNamespaces.entries())
          .filter(([p, uri]) => {
            // Include if:
            // 1. It's not in the parent's visible namespaces, or
            // 2. The URI is different from parent's
            return !visibleNamespaces.has(p) || visibleNamespaces.get(p) !== uri;
          })
          .sort((a, b) => {
            if (a[0] === "") return -1;
            if (b[0] === "") return 1;
            return a[0].localeCompare(b[0]);
          });

        for (const [prefix, uri] of nsEntries) {
          if (prefix === "") {
            result += ` xmlns="${uri}"`;
          } else {
            result += ` xmlns:${prefix}="${uri}"`;
          }
        }
      }

      // Handle attributes (sorted lexicographically)
      if (node.attributes) {
        const attrs = Array.from(node.attributes)
          .filter((attr) => !attr.name.startsWith("xmlns"))
          .sort((a, b) => a.name.localeCompare(b.name));

        for (const attr of attrs) {
          result += ` ${attr.name}="${XMLCanonicalizer.escapeXml(attr.value)}"`;
        }
      }

      result += ">";

      // Process children
      const children = Array.from(node.childNodes);
      let hasElementChildren = false;
      let lastWasElement = false;
      const hasMixedContent = node._whitespace?.hasMixedContent || false;

      // First pass to determine if we have element children
      for (const child of children) {
        if (child.nodeType === NODE_TYPES.ELEMENT_NODE) {
          hasElementChildren = true;
          break;
        }
      }

      // Check if we need to add a newline for c14n11
      // Don't add newlines for mixed content
      const needsInitialNewline =
        this.method.isCanonicalizationMethod === "c14n11" &&
        hasElementChildren &&
        !node._whitespace?.hasExistingLinebreaks &&
        !hasMixedContent;

      // Add newline for c14n11 if needed
      if (needsInitialNewline) {
        result += this.method.beforeChildren(hasElementChildren, hasMixedContent);
      }

      // Process each child
      for (let i = 0; i < children.length; i++) {
        const child = children[i];
        const isElement = child.nodeType === NODE_TYPES.ELEMENT_NODE;
        const nextChild = i < children.length - 1 ? children[i + 1] : null;
        const nextIsElement = nextChild && nextChild.nodeType === NODE_TYPES.ELEMENT_NODE;

        // Handle text node
        if (child.nodeType === NODE_TYPES.TEXT_NODE) {
          const text = child.nodeValue || "";

          if (XMLCanonicalizer.isBase64Element(node)) {
            // Special handling for base64 content
            result += text.replace(/\r/g, "&#xD;");
          } else {
            // Use the original text exactly as it was
            result += (child as NodeWithWhitespace)._originalText || text;
          }

          lastWasElement = false;
          continue;
        }

        // Handle element node
        if (isElement) {
          // Add newline between elements if needed for c14n11
          // Don't add newlines for mixed content
          if (
            lastWasElement &&
            this.method.isCanonicalizationMethod === "c14n11" &&
            !node._whitespace?.hasExistingLinebreaks &&
            !hasMixedContent
          ) {
            result += this.method.betweenChildren(true, true, hasMixedContent);
          }

          // Recursively canonicalize the child element
          result += this.canonicalize(child as NodeWithWhitespace, elementVisibleNamespaces, {
            isStartingNode: false,
          });

          lastWasElement = true;
        }
      }

      // Add final newline for c14n11 if needed
      // Don't add newlines for mixed content
      if (needsInitialNewline) {
        result += this.method.afterChildren(hasElementChildren, hasMixedContent);
      }

      result += "</" + qName + ">";
    } else if (node.nodeType === NODE_TYPES.TEXT_NODE) {
      // For standalone text nodes
      const text = (node as NodeWithWhitespace)._originalText || node.nodeValue || "";
      result += XMLCanonicalizer.escapeXml(text);
    }

    return result;
  }

  // Modified static methods that incorporate whitespace analysis
  static c14n(node: Node): string {
    // First analyze document whitespace
    this.analyzeWhitespace(node);

    // Then create canonicalizer and process the node
    const canonicalizer = new XMLCanonicalizer(methods.c14n);
    return canonicalizer.canonicalize(node as NodeWithWhitespace);
  }

  static c14n11(node: Node): string {
    // First analyze document whitespace
    this.analyzeWhitespace(node);

    // Then create canonicalizer and process the node
    const canonicalizer = new XMLCanonicalizer(methods.c14n11);
    return canonicalizer.canonicalize(node as NodeWithWhitespace);
  }

  static c14n_exc(node: Node): string {
    // First analyze document whitespace
    this.analyzeWhitespace(node);

    // Placeholder for exclusive canonicalization
    throw new Error("Exclusive canonicalization not yet implemented");
  }

  // New method that takes URI directly
  static canonicalize(node: Node, methodUri: string): string {
    // Get the method from the URI
    const methodKey =
      CANONICALIZATION_METHODS[methodUri as keyof typeof CANONICALIZATION_METHODS] ||
      CANONICALIZATION_METHODS.default;

    switch (methodKey) {
      case "c14n":
        return this.c14n(node);
      case "c14n11":
        return this.c14n11(node);
      case "c14n_exc":
        return this.c14n_exc(node);
      default:
        throw new Error(`Unsupported canonicalization method: ${methodUri}`);
    }
  }
}

export { XMLCanonicalizer, CANONICALIZATION_METHODS, NODE_TYPES };
