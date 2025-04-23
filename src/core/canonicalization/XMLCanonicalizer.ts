// Define types for canonicalization methods
interface CanonMethod {
  beforeChildren: (hasElementChildren?: boolean) => string;
  afterChildren: (hasElementChildren?: boolean) => string;
  betweenChildren: (prevIsElement?: boolean, nextIsElement?: boolean) => string;
  afterElement: () => string;
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
  },
  c14n11: {
    beforeChildren: (hasElementChildren?: boolean) => {
      return hasElementChildren ? "\n" : "";
    },
    afterChildren: (hasElementChildren?: boolean) => {
      return hasElementChildren ? "\n" : "";
    },
    betweenChildren: (prevIsElement?: boolean, nextIsElement?: boolean) => {
      return prevIsElement && nextIsElement ? "\n" : "";
    },
    afterElement: () => {
      return "";
    },
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

  canonicalize(
    node: Node,
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

      const prefix = node.prefix || "";
      const localName = node.localName || node.nodeName.split(":").pop() || "";
      const qName = prefix ? `${prefix}:${localName}` : localName;

      result += "<" + qName;

      // For the starting node, we need to include all in-scope namespaces
      if (options.isStartingNode) {
        // Collect all namespaces in scope for this element
        const allNamespaces = XMLCanonicalizer.collectNamespaces(node);

        // Include all namespaces that are in scope
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
        // For non-starting nodes, only include namespaces that are newly declared
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

      // Handle attributes
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

      for (let i = 0; i < children.length; i++) {
        const child = children[i];

        if (child.nodeType === NODE_TYPES.TEXT_NODE) {
          const isInBase64Element = XMLCanonicalizer.isBase64Element(node);
          const text = child.nodeValue || "";

          if (isInBase64Element) {
            result += text.replace(/\r/g, "&#xD;");
          } else {
            result += XMLCanonicalizer.escapeXml(text);
          }
        } else if (child.nodeType === NODE_TYPES.ELEMENT_NODE) {
          result += this.canonicalize(child, elementVisibleNamespaces, {
            isStartingNode: false,
          });
        }
      }

      result += "</" + qName + ">";
    } else if (node.nodeType === NODE_TYPES.TEXT_NODE) {
      const text = node.nodeValue || "";
      result += XMLCanonicalizer.escapeXml(text);
    }

    return result;
  }

  static c14n(node: Node): string {
    const canonicalizer = new XMLCanonicalizer(methods.c14n);
    return canonicalizer.canonicalize(node);
  }

  static c14n11(node: Node): string {
    const canonicalizer = new XMLCanonicalizer(methods.c14n11);
    return canonicalizer.canonicalize(node);
  }

  static c14n_exc(node: Node): string {
    // Placeholder for exclusive canonicalization
    throw new Error("Exclusive canonicalization not yet implemented");
  }
}

export { XMLCanonicalizer, CANONICALIZATION_METHODS, NODE_TYPES };
