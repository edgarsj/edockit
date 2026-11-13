// src/core/parser/signatureStructure.ts
//
// Strict, namespace-aware access to the parts of an XML signature. Every
// element used for verification is located by its exact position in the
// XMLDSig / XAdES structure, so the SignedInfo that is cryptographically
// verified is always the one whose references are evaluated.

export const DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
export const XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
export const XADES141_NS = "http://uri.etsi.org/01903/v1.4.1#";
export const SIGNED_PROPERTIES_TYPE_SUFFIX = "#SignedProperties";

const XADES_NAMESPACES = new Set([XADES_NS, XADES141_NS]);

function isElement(node: Node | null | undefined): node is Element {
  return !!node && node.nodeType === 1;
}

export function isElementNamed(node: Node | null | undefined, ns: string, localName: string) {
  return isElement(node) && node.namespaceURI === ns && node.localName === localName;
}

export function isXadesElement(node: Node | null | undefined, localName: string) {
  return (
    isElement(node) && XADES_NAMESPACES.has(node.namespaceURI || "") && node.localName === localName
  );
}

export function getChildElements(parent: Node | null | undefined): Element[] {
  const children: Element[] = [];
  if (!parent || !parent.childNodes) {
    return children;
  }
  for (let i = 0; i < parent.childNodes.length; i++) {
    const child = parent.childNodes[i];
    if (isElement(child)) {
      children.push(child);
    }
  }
  return children;
}

export function getDsigChildren(parent: Node | null | undefined, localName: string): Element[] {
  return getChildElements(parent).filter((child) => isElementNamed(child, DSIG_NS, localName));
}

export function getXadesChildren(parent: Node | null | undefined, localName: string): Element[] {
  return getChildElements(parent).filter((child) => isXadesElement(child, localName));
}

export function getSingleDsigChild(
  parent: Node | null | undefined,
  localName: string,
  required: true,
): Element;
export function getSingleDsigChild(
  parent: Node | null | undefined,
  localName: string,
  required?: false,
): Element | null;
export function getSingleDsigChild(
  parent: Node | null | undefined,
  localName: string,
  required = false,
): Element | null {
  const matches = getDsigChildren(parent, localName);
  if (matches.length > 1) {
    throw new Error(`Expected at most one ds:${localName} element, found ${matches.length}`);
  }
  if (matches.length === 0) {
    if (required) {
      throw new Error(`ds:${localName} element not found`);
    }
    return null;
  }
  return matches[0];
}

export function getSingleXadesChild(
  parent: Node | null | undefined,
  localName: string,
): Element | null {
  const matches = getXadesChildren(parent, localName);
  if (matches.length > 1) {
    throw new Error(`Expected at most one xades:${localName} element, found ${matches.length}`);
  }
  return matches[0] ?? null;
}

/**
 * Locate the top-level ds:Signature elements of a signature document.
 *
 * Accepted shapes: the document element is itself a ds:Signature, or the
 * ds:Signature elements are direct children of the document element (ASiC
 * `asic:XAdESSignatures`, Latvian eDoc `XAdESSignatures`). Signatures nested
 * deeper (e.g. counter-signatures, or anything inside ds:Object) are never
 * treated as the document's signature.
 */
export function locateTopLevelSignatures(doc: Document): Element[] {
  const root = doc.documentElement;
  if (!root) {
    return [];
  }
  if (isElementNamed(root, DSIG_NS, "Signature")) {
    return [root];
  }
  return getDsigChildren(root, "Signature");
}

/**
 * Locate xades:UnsignedSignatureProperties of a signature via
 * ds:Object/xades:QualifyingProperties/xades:UnsignedProperties.
 */
export function getUnsignedSignatureProperties(signature: Element): Element | null {
  for (const object of getDsigChildren(signature, "Object")) {
    for (const qualifyingProperties of getXadesChildren(object, "QualifyingProperties")) {
      for (const unsignedProperties of getXadesChildren(
        qualifyingProperties,
        "UnsignedProperties",
      )) {
        const unsignedSignatureProperties = getXadesChildren(
          unsignedProperties,
          "UnsignedSignatureProperties",
        )[0];
        if (unsignedSignatureProperties) {
          return unsignedSignatureProperties;
        }
      }
    }
  }
  return null;
}

export interface SignatureParts {
  signature: Element;
  signedInfo: Element;
  signatureValue: Element;
  keyInfo: Element | null;
  references: Element[];
}

/**
 * Resolve the structural parts of a ds:Signature using only direct children,
 * per the XMLDSig schema.
 */
export function getSignatureParts(signature: Element): SignatureParts {
  const signedInfo = getSingleDsigChild(signature, "SignedInfo", true);
  const signatureValue = getSingleDsigChild(signature, "SignatureValue", true);
  const keyInfo = getSingleDsigChild(signature, "KeyInfo");
  const references = getDsigChildren(signedInfo, "Reference");

  return { signature, signedInfo, signatureValue, keyInfo, references };
}

/**
 * Find elements whose `Id` attribute equals `id` anywhere in the document.
 * XAdES and XMLDSig identify same-document reference targets by `Id`.
 */
export function findElementsById(doc: Document, id: string): Element[] {
  const results: Element[] = [];
  const stack: Node[] = doc.documentElement ? [doc.documentElement] : [];

  while (stack.length > 0) {
    const node = stack.pop()!;
    if (!isElement(node)) {
      continue;
    }
    if (node.getAttribute("Id") === id) {
      results.push(node);
    }
    const children = node.childNodes;
    for (let i = children.length - 1; i >= 0; i--) {
      if (isElement(children[i])) {
        stack.push(children[i]);
      }
    }
  }

  return results;
}

/**
 * Resolve a same-document reference (`#id`) to exactly one element.
 * Ambiguous identifiers are rejected.
 */
export function resolveSameDocumentReference(doc: Document, uri: string): Element {
  if (!uri.startsWith("#") || uri.length < 2) {
    throw new Error(`Not a same-document reference: "${uri}"`);
  }
  const id = uri.slice(1);
  const matches = findElementsById(doc, id);
  if (matches.length === 0) {
    throw new Error(`Reference target "${uri}" not found`);
  }
  if (matches.length > 1) {
    throw new Error(
      `Reference target "${uri}" is ambiguous (${matches.length} elements share the Id)`,
    );
  }
  return matches[0];
}

export function isSignedPropertiesReference(reference: Element): boolean {
  const type = reference.getAttribute("Type") || "";
  return type.endsWith(SIGNED_PROPERTIES_TYPE_SUFFIX);
}

/**
 * Get the text content of an element with all whitespace removed (for base64
 * values and digests).
 */
export function getCompactText(element: Element | null | undefined): string {
  return element?.textContent?.replace(/\s+/g, "") || "";
}
