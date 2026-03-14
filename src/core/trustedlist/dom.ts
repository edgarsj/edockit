import { createXMLParser } from "../../utils/xmlParser";

type XmlParent = Document | Element;

function isElement(node: Node | null | undefined): node is Element {
  return Boolean(node && node.nodeType === 1);
}

function localNameMatches(
  node: Node | null | undefined,
  expectedLocalName: string,
): node is Element {
  if (!isElement(node)) {
    return false;
  }

  return (
    node.localName === expectedLocalName ||
    node.nodeName === expectedLocalName ||
    node.nodeName.endsWith(`:${expectedLocalName}`)
  );
}

function getChildNodes(parent: XmlParent): Node[] {
  const childNodes =
    "documentElement" in parent && parent.documentElement
      ? parent.documentElement.childNodes
      : parent.childNodes;
  const nodes: Node[] = [];

  for (let index = 0; index < childNodes.length; index += 1) {
    nodes.push(childNodes[index]);
  }

  return nodes;
}

function walkDescendants(parent: XmlParent, callback: (element: Element) => boolean | void) {
  const visit = (node: Node): boolean => {
    if (isElement(node)) {
      if (callback(node)) {
        return true;
      }
    }

    if (!node.childNodes) {
      return false;
    }

    for (let index = 0; index < node.childNodes.length; index += 1) {
      if (visit(node.childNodes[index])) {
        return true;
      }
    }

    return false;
  };

  const startingNodes =
    "documentElement" in parent && parent.documentElement
      ? [parent.documentElement]
      : getChildNodes(parent);

  for (const node of startingNodes) {
    if (visit(node)) {
      return;
    }
  }
}

export function parseXmlDocument(xml: string): Document {
  return createXMLParser().parseFromString(xml, "application/xml");
}

export function getDocumentElement(document: Document): Element | null {
  return document.documentElement || null;
}

export function getChildElement(parent: XmlParent | null, localName: string): Element | null {
  if (!parent) {
    return null;
  }

  for (const childNode of getChildNodes(parent)) {
    if (localNameMatches(childNode, localName)) {
      return childNode;
    }
  }

  return null;
}

export function getChildElements(parent: XmlParent | null, localName: string): Element[] {
  if (!parent) {
    return [];
  }

  return getChildNodes(parent).filter((childNode): childNode is Element =>
    localNameMatches(childNode, localName),
  );
}

export function getDescendantElement(parent: XmlParent | null, localName: string): Element | null {
  if (!parent) {
    return null;
  }

  let foundElement: Element | null = null;

  walkDescendants(parent, (element) => {
    if (!foundElement && localNameMatches(element, localName)) {
      foundElement = element;
      return true;
    }

    return false;
  });

  return foundElement;
}

export function getDescendantElements(parent: XmlParent | null, localName: string): Element[] {
  if (!parent) {
    return [];
  }

  const elements: Element[] = [];

  walkDescendants(parent, (element) => {
    if (localNameMatches(element, localName)) {
      elements.push(element);
    }
  });

  return elements;
}

export function getElementText(element: Element | null | undefined): string | undefined {
  const textContent = element?.textContent?.trim();
  return textContent || undefined;
}

export function getChildText(parent: XmlParent | null, localName: string): string | undefined {
  return getElementText(getChildElement(parent, localName));
}

export function getDescendantText(parent: XmlParent | null, localName: string): string | undefined {
  return getElementText(getDescendantElement(parent, localName));
}

export function getLanguageAttribute(element: Element): string | undefined {
  const language =
    element.getAttribute("xml:lang") ||
    element.getAttribute("lang") ||
    element.getAttributeNS("http://www.w3.org/XML/1998/namespace", "lang");

  return language?.trim() || undefined;
}
