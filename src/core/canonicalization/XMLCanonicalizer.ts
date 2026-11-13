// Define types for canonicalization methods
/**
 * Text and CDATA sections are both character data: Canonical XML replaces
 * CDATA sections with their (escaped) character content.
 */
function isCharacterData(node: Node | null | undefined): boolean {
  return (
    !!node &&
    (node.nodeType === NODE_TYPES.TEXT_NODE || node.nodeType === NODE_TYPES.CDATA_SECTION_NODE)
  );
}

/** Canonical form of a processing instruction inside the document element. */
function renderProcessingInstruction(node: Node): string {
  const pi = node as ProcessingInstruction;
  const data = pi.data || pi.nodeValue || "";
  return `<?${pi.target || pi.nodeName}${data ? ` ${data}` : ""}?>`;
}

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
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": "c14n",
  "http://www.w3.org/2006/12/xml-c14n11": "c14n11",
  "http://www.w3.org/2006/12/xml-c14n11#WithComments": "c14n11",
  "http://www.w3.org/2001/10/xml-exc-c14n#": "c14n_exc",
  "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": "c14n_exc",
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
    // C14N 1.1 should NOT add newlines - it should preserve original whitespace
    // The difference from C14N is in xml:id normalization, not formatting
    beforeChildren: () => "",
    afterChildren: () => "",
    betweenChildren: () => "",
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
  CDATA_SECTION_NODE: 4,
  PROCESSING_INSTRUCTION_NODE: 7,
  COMMENT_NODE: 8,
};

// Options for exclusive canonicalization
interface ExcC14NOptions {
  inclusiveNamespacePrefixList?: string[];
  isStartingNode?: boolean;
}

interface CanonicalizeOptions {
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

const XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace";

class XMLCanonicalizer {
  private method: CanonMethod;
  /** Render comment nodes (the #WithComments variants) */
  private withComments: boolean;

  constructor(method: CanonMethod = methods.c14n, withComments = false) {
    this.method = method;
    this.withComments = withComments;
  }

  /**
   * xml:* attributes inherited from ancestors that are not set on `element`
   * (nearest ancestor wins).
   */
  private collectInheritedXmlAttributes(element: Element): Attr[] {
    const isC14n11 = this.method.isCanonicalizationMethod === "c14n11";
    const own = new Set<string>();
    for (let i = 0; i < element.attributes.length; i++) {
      const attr = element.attributes[i];
      if (attr.name.startsWith("xml:")) {
        own.add(attr.name);
      }
    }

    const inherited = new Map<string, Attr>();
    let current = element.parentNode;
    while (current && current.nodeType === NODE_TYPES.ELEMENT_NODE) {
      const ancestor = current as Element;
      for (let i = 0; i < ancestor.attributes.length; i++) {
        const attr = ancestor.attributes[i];
        if (!attr.name.startsWith("xml:") || own.has(attr.name) || inherited.has(attr.name)) {
          continue;
        }
        if (isC14n11 && attr.name !== "xml:lang" && attr.name !== "xml:space") {
          continue;
        }
        inherited.set(attr.name, attr);
      }
      current = current.parentNode;
    }

    return Array.from(inherited.values()).map(
      (attr) =>
        ({
          name: attr.name,
          value: attr.value,
          localName: attr.name.substring(4),
          namespaceURI: XML_NAMESPACE,
        }) as unknown as Attr,
    );
  }

  /** Canonical form of a comment node, or "" when comments are omitted. */
  private renderComment(node: Node): string {
    return this.withComments ? `<!--${node.nodeValue || ""}-->` : "";
  }

  // Static method to get canonicalizer by URI
  static fromMethod(methodUri: string): XMLCanonicalizer {
    const methodKey = CANONICALIZATION_METHODS[methodUri as keyof typeof CANONICALIZATION_METHODS];
    if (!methodKey) {
      throw new Error(`Unsupported canonicalization method: ${methodUri}`);
    }
    return new XMLCanonicalizer(methods[methodKey], methodUri.endsWith("#WithComments"));
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

  /** Escape text node content per Canonical XML (&, <, >, CR). */
  static escapeText(text: string): string {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\r/g, "&#xD;");
  }

  /** Escape attribute values per Canonical XML (&, <, ", TAB, LF, CR). */
  static escapeAttribute(value: string): string {
    return value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/"/g, "&quot;")
      .replace(/\t/g, "&#x9;")
      .replace(/\n/g, "&#xA;")
      .replace(/\r/g, "&#xD;");
  }

  /** Compare attributes by namespace URI, then local name (code point order). */
  static compareAttributes(a: Attr, b: Attr): number {
    const nsA = a.namespaceURI || "";
    const nsB = b.namespaceURI || "";
    if (nsA !== nsB) {
      return nsA < nsB ? -1 : 1;
    }
    const nameA = a.localName || a.name;
    const nameB = b.localName || b.name;
    return nameA < nameB ? -1 : nameA > nameB ? 1 : 0;
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
          if (isCharacterData(child)) {
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

          if (isCharacterData(child)) {
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

  canonicalize(
    node: NodeWithWhitespace,
    visibleNamespaces = new Map<string, string>(),
    options: CanonicalizeOptions = { isStartingNode: true },
  ): string {
    if (this.method.isCanonicalizationMethod === "c14n_exc") {
      return this.canonicalizeExclusive(node, visibleNamespaces, {
        inclusiveNamespacePrefixList: options.inclusiveNamespacePrefixList,
        isStartingNode: options.isStartingNode,
      });
    }

    return this.canonicalizeStandard(node, visibleNamespaces, {
      isStartingNode: options.isStartingNode ?? true,
    });
  }

  // Standard canonicalization method
  private canonicalizeStandard(
    node: NodeWithWhitespace,
    visibleNamespaces = new Map<string, string>(),
    options = { isStartingNode: true },
  ): string {
    if (!node) return "";

    let result = "";

    if (node.nodeType === NODE_TYPES.ELEMENT_NODE) {
      const element = node as Element & NodeWithWhitespace;

      // Namespace context passed down to children: everything in scope here.
      // For the starting node that includes namespaces inherited from
      // ancestors, which are rendered on it (inclusive canonicalization).
      let elementVisibleNamespaces: Map<string, string>;
      let namespacesToRender: Array<[string, string]>;

      if (options.isStartingNode) {
        elementVisibleNamespaces = XMLCanonicalizer.collectNamespaces(node);
        namespacesToRender = Array.from(elementVisibleNamespaces.entries()).filter(
          ([nsPrefix, uri]) => !(nsPrefix === "" && uri === ""),
        );
      } else {
        elementVisibleNamespaces = new Map(visibleNamespaces);
        const xmlnsAttr = element.getAttribute("xmlns");
        if (xmlnsAttr !== null) {
          elementVisibleNamespaces.set("", xmlnsAttr);
        }
        const nsAttrs = element.attributes;
        for (let i = 0; i < nsAttrs.length; i++) {
          const attr = nsAttrs[i];
          if (attr.name.startsWith("xmlns:")) {
            elementVisibleNamespaces.set(attr.name.substring(6), attr.value);
          }
        }
        // Only declarations that change the namespace context are rendered
        namespacesToRender = Array.from(elementVisibleNamespaces.entries()).filter(
          ([nsPrefix, uri]) =>
            (visibleNamespaces.get(nsPrefix) ?? "") !== uri ||
            (nsPrefix !== "" && !visibleNamespaces.has(nsPrefix)),
        );
      }

      namespacesToRender.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

      // Prepare the element's start tag
      const prefix = element.prefix || "";
      const localName = element.localName || element.nodeName.split(":").pop() || "";
      const qName = prefix ? `${prefix}:${localName}` : localName;

      result += "<" + qName;

      for (const [nsPrefix, uri] of namespacesToRender) {
        if (nsPrefix === "") {
          result += ` xmlns="${XMLCanonicalizer.escapeAttribute(uri)}"`;
        } else {
          result += ` xmlns:${nsPrefix}="${XMLCanonicalizer.escapeAttribute(uri)}"`;
        }
      }

      // Handle attributes (sorted lexicographically)
      const elementAttrs = element.attributes;
      const attrArray: Attr[] = [];

      for (let i = 0; i < elementAttrs.length; i++) {
        const attr = elementAttrs[i];
        if (!attr.name.startsWith("xmlns")) {
          attrArray.push(attr);
        }
      }

      // Inclusive canonicalization of a subtree carries over xml:* attributes
      // in scope from ancestors (C14N 1.1: only xml:lang and xml:space)
      if (options.isStartingNode) {
        attrArray.push(...this.collectInheritedXmlAttributes(element));
      }

      attrArray.sort(XMLCanonicalizer.compareAttributes);

      for (const attr of attrArray) {
        result += ` ${attr.name}="${XMLCanonicalizer.escapeAttribute(attr.value)}"`;
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
        if (isCharacterData(child)) {
          const text = child.nodeValue || "";

          // Character data is escaped per Canonical XML (&, <, >, CR)
          result += XMLCanonicalizer.escapeText(child._originalText || text);

          lastWasElement = false;
          continue;
        }

        // Processing instructions are retained
        if (child.nodeType === NODE_TYPES.PROCESSING_INSTRUCTION_NODE) {
          result += renderProcessingInstruction(child);
          lastWasElement = false;
          continue;
        }

        // Comments only in the #WithComments variants
        if (child.nodeType === NODE_TYPES.COMMENT_NODE) {
          result += this.renderComment(child);
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
          result += this.canonicalizeStandard(child, elementVisibleNamespaces, {
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
    } else if (isCharacterData(node)) {
      // For standalone text nodes
      const text = node._originalText || node.nodeValue || "";
      result += XMLCanonicalizer.escapeText(text);
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

      // Namespaces in scope for this element (nearest declaration wins)
      const inScopeNamespaces = XMLCanonicalizer.collectNamespaces(element);
      // Namespaces already rendered by output ancestors
      const renderedNamespaces = isStartingNode ? new Map<string, string>() : visibleNamespaces;

      // Exclusive XML Canonicalization: a namespace declaration is rendered on
      // an element only if the element visibly utilizes it (element or
      // attribute prefix) or it is listed in InclusiveNamespaces, and it has
      // not already been rendered with the same value by an output ancestor.
      const neededNamespaces = new Map<string, string>();
      const elementPrefix = element.prefix || "";
      const elementNamespace = element.namespaceURI || "";
      if (elementPrefix) {
        neededNamespaces.set(elementPrefix, elementNamespace);
      } else if (elementNamespace || (renderedNamespaces.get("") ?? "") !== "") {
        neededNamespaces.set("", elementNamespace);
      }

      for (let i = 0; i < element.attributes.length; i++) {
        const attr = element.attributes[i];
        if (attr.name === "xmlns" || attr.name.startsWith("xmlns:")) {
          continue;
        }
        const attrPrefix = attr.prefix || (attr.name.includes(":") ? attr.name.split(":")[0] : "");
        if (attrPrefix && attrPrefix !== "xml") {
          const uri = attr.namespaceURI || inScopeNamespaces.get(attrPrefix);
          if (uri) {
            neededNamespaces.set(attrPrefix, uri);
          }
        }
      }

      for (const listedPrefix of inclusiveNamespacePrefixList) {
        const key = listedPrefix === "#default" ? "" : listedPrefix;
        const uri = inScopeNamespaces.get(key);
        if (uri !== undefined && !neededNamespaces.has(key)) {
          neededNamespaces.set(key, uri);
        }
      }

      const namespacesToRender = Array.from(neededNamespaces.entries())
        .filter(([nsPrefix, uri]) => {
          if (nsPrefix === "" && uri === "" && !renderedNamespaces.has("")) {
            return false;
          }
          return renderedNamespaces.get(nsPrefix) !== uri;
        })
        .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

      const usedNamespaces = new Map<string, string>(namespacesToRender);

      // Start the element opening tag
      const prefix = element.prefix || "";
      const localName = element.localName || element.nodeName.split(":").pop() || "";
      const qName = prefix ? `${prefix}:${localName}` : localName;

      result += "<" + qName;

      for (const [nsPrefix, uri] of namespacesToRender) {
        if (nsPrefix === "") {
          result += ` xmlns="${XMLCanonicalizer.escapeAttribute(uri)}"`;
        } else {
          result += ` xmlns:${nsPrefix}="${XMLCanonicalizer.escapeAttribute(uri)}"`;
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

      attrArray.sort(XMLCanonicalizer.compareAttributes);

      for (const attr of attrArray) {
        result += ` ${attr.name}="${XMLCanonicalizer.escapeAttribute(attr.value)}"`;
      }

      result += ">";

      // Process child nodes
      const children = Array.from(node.childNodes);

      for (let i = 0; i < children.length; i++) {
        const child = children[i] as NodeWithWhitespace;

        if (isCharacterData(child)) {
          const text = child.nodeValue || "";

          // Character data is escaped per Canonical XML (&, <, >, CR)
          result += XMLCanonicalizer.escapeText(text);
        } else if (child.nodeType === NODE_TYPES.PROCESSING_INSTRUCTION_NODE) {
          // Processing instructions are retained
          result += renderProcessingInstruction(child);
        } else if (child.nodeType === NODE_TYPES.COMMENT_NODE) {
          // Comments only in the #WithComments variants
          result += this.renderComment(child);
        } else if (child.nodeType === NODE_TYPES.ELEMENT_NODE) {
          // Recursively process child elements
          // For child elements, we pass the namespaces from the parent but mark as non-root
          result += this.canonicalizeExclusive(
            child,
            new Map([...renderedNamespaces, ...usedNamespaces]), // Namespaces rendered so far
            {
              inclusiveNamespacePrefixList,
              isStartingNode: false, // Mark as non-starting node
            },
          );
        }
      }

      // Close the element
      result += "</" + qName + ">";
    } else if (isCharacterData(node)) {
      // Handle standalone text node
      const text = node.nodeValue || "";
      result += XMLCanonicalizer.escapeText(text);
    }

    return result;
  }

  // Static methods for canonicalization
  static c14n(node: Node, withComments = false): string {
    // First analyze document whitespace
    this.analyzeWhitespace(node);

    // Then create canonicalizer and process the node
    const canonicalizer = new XMLCanonicalizer(methods.c14n, withComments);
    return canonicalizer.canonicalize(node as NodeWithWhitespace);
  }

  static c14n11(node: Node, withComments = false): string {
    // First analyze document whitespace
    this.analyzeWhitespace(node);

    // Then create canonicalizer and process the node
    const canonicalizer = new XMLCanonicalizer(methods.c14n11, withComments);
    return canonicalizer.canonicalize(node as NodeWithWhitespace);
  }

  static c14n_exc(
    node: Node,
    inclusiveNamespacePrefixList: string[] = [],
    withComments = false,
  ): string {
    // First analyze document whitespace
    this.analyzeWhitespace(node);

    // Create canonicalizer and process the node with exclusive canonicalization
    const canonicalizer = new XMLCanonicalizer(methods.c14n_exc, withComments);
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

    const withComments = methodUri.endsWith("#WithComments");

    switch (methodKey) {
      case "c14n":
        return this.c14n(node, withComments);
      case "c14n11":
        return this.c14n11(node, withComments);
      case "c14n_exc":
        return this.c14n_exc(node, options.inclusiveNamespacePrefixList || [], withComments);
      default:
        throw new Error(`Unsupported canonicalization method: ${methodUri}`);
    }
  }
}

export { XMLCanonicalizer, CANONICALIZATION_METHODS, NODE_TYPES };
