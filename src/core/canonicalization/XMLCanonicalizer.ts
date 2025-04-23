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
    beforeChildren: () => "",
    afterChildren: () => "",
    betweenChildren: () => "",
    afterElement: () => "",
    isCanonicalizationMethod: "c14n_exc",
  },
};

// Define these constants as they're used in the code
const NODE_TYPES = {
  ELEMENT_NODE: 1,
  TEXT_NODE: 3,
};

// Options for exclusive canonicalization
interface ExcC14NOptions {
  inclusiveNamespacePrefixList?: string[];
  isStartingNode?: boolean;
}

// Whitespace information to track
interface WhitespaceInfo {
  hasMixedContent?: boolean; // Whether element has both elements and text
  hasExistingLinebreaks?: boolean; // Whether element already has linebreaks
  originalContent?: Record<string, any>; // Original content and whitespace info
}

// Custom type for nodes with whitespace information
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

  // Helper method to collect namespaces from ancestors
  static collectNamespaces(
    node: Node,
    visibleNamespaces = new Map<string, string>(),
  ): Map<string, string> {
    let current: Node | null = node;

    while (current && current.nodeType === NODE_TYPES.ELEMENT_NODE) {
      const element = current as Element;

      // Handle default namespace
      const xmlnsAttr = element.getAttribute("xmlns");
      if (xmlnsAttr !== null && !visibleNamespaces.has("")) {
        visibleNamespaces.set("", xmlnsAttr);
      }

      // Handle prefixed namespaces
      const attrs = element.attributes;
      for (let i = 0; i < attrs.length; i++) {
        const attr = attrs[i];
        if (attr.name.startsWith("xmlns:")) {
          const prefix = attr.name.substring(6);
          if (!visibleNamespaces.has(prefix)) {
            visibleNamespaces.set(prefix, attr.value);
          }
        }
      }

      current = current.parentNode;
    }

    return visibleNamespaces;
  }

  // Helper method to collect namespaces used in the specific element and its descendants
  static collectUsedNamespaces(
    node: Node,
    allVisibleNamespaces = new Map<string, string>(),
    inclusivePrefixList: string[] = [],
  ): Map<string, string> {
    const usedNamespaces = new Map<string, string>();
    const visitedPrefixes = new Set<string>(); // Track prefixes we've already processed

    // Recursive function to check for namespace usage
    function processNode(currentNode: Node, isRoot: boolean = false): void {
      if (currentNode.nodeType === NODE_TYPES.ELEMENT_NODE) {
        const element = currentNode as Element;

        // Check element's namespace
        const elementNs = element.namespaceURI;
        const elementPrefix = element.prefix || "";

        if (elementPrefix && elementNs) {
          // If this is the root element or a prefix we haven't seen yet
          if (isRoot || !visitedPrefixes.has(elementPrefix)) {
            visitedPrefixes.add(elementPrefix);

            // If the namespace URI matches what we have in allVisibleNamespaces for this prefix
            const nsUri = allVisibleNamespaces.get(elementPrefix);
            if (nsUri && nsUri === elementNs && !usedNamespaces.has(elementPrefix)) {
              usedNamespaces.set(elementPrefix, nsUri);
            }
          }
        }

        // Check attributes for namespaces
        const attrs = element.attributes;
        for (let i = 0; i < attrs.length; i++) {
          const attr = attrs[i];
          if (attr.name.includes(":") && !attr.name.startsWith("xmlns:")) {
            const attrPrefix = attr.name.split(":")[0];

            // Only process this prefix if we haven't seen it before or it's the root element
            if (isRoot || !visitedPrefixes.has(attrPrefix)) {
              visitedPrefixes.add(attrPrefix);

              const nsUri = allVisibleNamespaces.get(attrPrefix);
              if (nsUri && !usedNamespaces.has(attrPrefix)) {
                usedNamespaces.set(attrPrefix, nsUri);
              }
            }
          }
        }

        // Include namespaces from inclusivePrefixList
        for (const prefix of inclusivePrefixList) {
          const nsUri = allVisibleNamespaces.get(prefix);
          if (nsUri && !usedNamespaces.has(prefix)) {
            usedNamespaces.set(prefix, nsUri);
          }
        }

        // Process child nodes
        for (let i = 0; i < currentNode.childNodes.length; i++) {
          processNode(currentNode.childNodes[i], false);
        }
      }
    }

    processNode(node, true); // Start with root = true
    return usedNamespaces;
  }

  static isBase64Element(node: Node): boolean {
    if (node.nodeType !== NODE_TYPES.ELEMENT_NODE) return false;

    const element = node as Element;
    const localName = element.localName || element.nodeName.split(":").pop() || "";

    return this.base64Elements.has(localName);
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
          const child = children[i] as NodeWithWhitespace;

          if (child.nodeType === NODE_TYPES.TEXT_NODE) {
            const text = child.nodeValue || "";

            // Store original text
            child._originalText = text;

            // Check for linebreaks in text
            if (text.includes("\n")) {
              hasLinebreaks = true;
            }
          } else if (child.nodeType === NODE_TYPES.ELEMENT_NODE) {
            // Recursively analyze child elements
            analyzeNode(child);
          }
        }

        // Set mixed content flag - true if there's both text content and element children
        node._whitespace.hasMixedContent = hasTextContent && hasElementContent;
        node._whitespace.hasExistingLinebreaks = hasLinebreaks;
      }
    }

    analyzeNode(rootNode as NodeWithWhitespace);
  }

  // Standard canonicalization method
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
      const element = node as Element & NodeWithWhitespace;

      // Collect namespaces declared on this element
      // Handle default namespace
      const xmlnsAttr = element.getAttribute("xmlns");
      if (xmlnsAttr !== null) {
        elementVisibleNamespaces.set("", xmlnsAttr);
      }

      // Handle prefixed namespaces
      const nsAttrs = element.attributes;
      for (let i = 0; i < nsAttrs.length; i++) {
        const attr = nsAttrs[i];
        if (attr.name.startsWith("xmlns:")) {
          const prefix = attr.name.substring(6);
          elementVisibleNamespaces.set(prefix, attr.value);
        }
      }

      // Prepare the element's start tag
      const prefix = element.prefix || "";
      const localName = element.localName || element.nodeName.split(":").pop() || "";
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
      const elementAttrs = element.attributes;
      const attrArray = [];

      for (let i = 0; i < elementAttrs.length; i++) {
        const attr = elementAttrs[i];
        if (!attr.name.startsWith("xmlns")) {
          attrArray.push(attr);
        }
      }

      attrArray.sort((a, b) => a.name.localeCompare(b.name));

      for (const attr of attrArray) {
        result += ` ${attr.name}="${XMLCanonicalizer.escapeXml(attr.value)}"`;
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
        const child = children[i] as NodeWithWhitespace;
        const isElement = child.nodeType === NODE_TYPES.ELEMENT_NODE;
        const nextChild = i < children.length - 1 ? (children[i + 1] as Node) : null;
        const nextIsElement = nextChild && nextChild.nodeType === NODE_TYPES.ELEMENT_NODE;

        // Handle text node
        if (child.nodeType === NODE_TYPES.TEXT_NODE) {
          const text = child.nodeValue || "";

          if (XMLCanonicalizer.isBase64Element(node)) {
            // Special handling for base64 content
            result += text.replace(/\r/g, "&#xD;");
          } else {
            // Use the original text exactly as it was
            result += child._originalText || text;
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
          result += this.canonicalize(child, elementVisibleNamespaces, {
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
      const text = node._originalText || node.nodeValue || "";
      result += XMLCanonicalizer.escapeXml(text);
    }

    return result;
  }

  // Exclusive canonicalization implementation
  canonicalizeExclusive(
    node: NodeWithWhitespace,
    visibleNamespaces = new Map<string, string>(),
    options: ExcC14NOptions = {},
  ): string {
    if (!node) return "";

    const { inclusiveNamespacePrefixList = [], isStartingNode = true } = options;
    let result = "";

    if (node.nodeType === NODE_TYPES.ELEMENT_NODE) {
      const element = node as Element & NodeWithWhitespace;

      // First, collect all namespaces that are visible at this point
      const allVisibleNamespaces = XMLCanonicalizer.collectNamespaces(element);

      // Then, determine which namespaces are actually used in this subtree
      const usedNamespaces = isStartingNode
        ? XMLCanonicalizer.collectUsedNamespaces(
            element,
            allVisibleNamespaces,
            inclusiveNamespacePrefixList,
          )
        : new Map<string, string>(); // For child elements, don't add any more namespaces

      // Start the element opening tag
      const prefix = element.prefix || "";
      const localName = element.localName || element.nodeName.split(":").pop() || "";
      const qName = prefix ? `${prefix}:${localName}` : localName;

      result += "<" + qName;

      // Add namespace declarations for used namespaces (only at the top level)
      if (isStartingNode) {
        const nsEntries = Array.from(usedNamespaces.entries()).sort((a, b) => {
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

      // Add attributes (sorted lexicographically)
      const elementAttrs = element.attributes;
      const attrArray = [];

      for (let i = 0; i < elementAttrs.length; i++) {
        const attr = elementAttrs[i];
        if (!attr.name.startsWith("xmlns")) {
          attrArray.push(attr);
        }
      }

      attrArray.sort((a, b) => a.name.localeCompare(b.name));

      for (const attr of attrArray) {
        result += ` ${attr.name}="${XMLCanonicalizer.escapeXml(attr.value)}"`;
      }

      result += ">";

      // Process child nodes
      const children = Array.from(node.childNodes);

      for (let i = 0; i < children.length; i++) {
        const child = children[i] as NodeWithWhitespace;

        if (child.nodeType === NODE_TYPES.TEXT_NODE) {
          const text = child.nodeValue || "";

          if (XMLCanonicalizer.isBase64Element(node)) {
            // Special handling for base64 content
            result += text.replace(/\r/g, "&#xD;");
          } else {
            // Regular text handling
            result += XMLCanonicalizer.escapeXml(text);
          }
        } else if (child.nodeType === NODE_TYPES.ELEMENT_NODE) {
          // Recursively process child elements
          // For child elements, we pass the namespaces from the parent but mark as non-root
          result += this.canonicalizeExclusive(
            child,
            new Map([...visibleNamespaces, ...usedNamespaces]), // Pass all namespaces to children
            {
              inclusiveNamespacePrefixList,
              isStartingNode: false, // Mark as non-starting node
            },
          );
        }
      }

      // Close the element
      result += "</" + qName + ">";
    } else if (node.nodeType === NODE_TYPES.TEXT_NODE) {
      // Handle standalone text node
      const text = node.nodeValue || "";
      result += XMLCanonicalizer.escapeXml(text);
    }

    return result;
  }

  // Static methods for canonicalization
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

  static c14n_exc(node: Node, inclusiveNamespacePrefixList: string[] = []): string {
    // First analyze document whitespace
    this.analyzeWhitespace(node);

    // Create canonicalizer and process the node with exclusive canonicalization
    const canonicalizer = new XMLCanonicalizer(methods.c14n_exc);
    return canonicalizer.canonicalizeExclusive(node as NodeWithWhitespace, new Map(), {
      inclusiveNamespacePrefixList,
    });
  }

  // Method that takes URI directly
  static canonicalize(node: Node, methodUri: string, options: any = {}): string {
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
        return this.c14n_exc(node, options.inclusiveNamespacePrefixList || []);
      default:
        throw new Error(`Unsupported canonicalization method: ${methodUri}`);
    }
  }
}

export { XMLCanonicalizer, CANONICALIZATION_METHODS, NODE_TYPES };
