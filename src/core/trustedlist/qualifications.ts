import { getChildElement, getChildElements } from "./dom";
import type { QualificationCriteriaList, QualificationElement } from "./types";

/** AdditionalServiceInformation mask bits used in compact bundles */
export const ASI_FOR_ESIGNATURES = 1;
export const ASI_FOR_ESEALS = 2;
export const ASI_FOR_WEBSITE_AUTHENTICATION = 4;

function localName(element: Element): string {
  return element.localName || element.nodeName.split(":").pop() || "";
}

function childElements(parent: Element): Element[] {
  const elements: Element[] = [];
  for (let node = parent.firstChild; node; node = node.nextSibling) {
    if (node.nodeType === 1) {
      elements.push(node as Element);
    }
  }
  return elements;
}

function text(element: Element | null | undefined): string {
  return element?.textContent?.trim() ?? "";
}

/** Last path segment of an ETSI URI, e.g. ".../SvcInfoExt/QCWithQSCD" -> "QCWithQSCD" */
export function getUriSuffix(uri: string): string {
  const trimmed = uri.trim().replace(/\/+$/, "");
  return trimmed.slice(trimmed.lastIndexOf("/") + 1);
}

/** "urn:oid:1.2.3" -> "1.2.3" */
export function normalizeOid(value: string): string {
  return value
    .trim()
    .replace(/^urn:oid:/i, "")
    .trim();
}

function collectIdentifiers(element: Element, names: string[]): string[] {
  const result: string[] = [];
  const visit = (current: Element) => {
    for (const child of childElements(current)) {
      if (names.includes(localName(child))) {
        const value = normalizeOid(text(child));
        if (value) {
          result.push(value);
        }
      } else {
        visit(child);
      }
    }
  };
  visit(element);
  return result;
}

function parseCriteriaList(element: Element): QualificationCriteriaList {
  const assertValue = element.getAttribute("assert");
  const criteria: QualificationCriteriaList = {
    assert: assertValue === "all" || assertValue === "none" ? assertValue : "atLeastOne",
  };
  if (assertValue !== "all" && assertValue !== "none" && assertValue !== "atLeastOne") {
    criteria.unsupported = true;
  }

  for (const child of childElements(element)) {
    switch (localName(child)) {
      case "KeyUsage": {
        const bits: Record<string, boolean> = {};
        for (const bit of getChildElements(child, "KeyUsageBit")) {
          const name = bit.getAttribute("name");
          if (name) {
            bits[name] = text(bit).toLowerCase() === "true";
          }
        }
        (criteria.keyUsage ??= []).push(bits);
        break;
      }
      case "PolicySet":
        (criteria.policySets ??= []).push(collectIdentifiers(child, ["Identifier"]));
        break;
      case "CriteriaList":
        (criteria.criteriaLists ??= []).push(parseCriteriaList(child));
        break;
      case "otherCriteriaList":
        for (const other of childElements(child)) {
          const otherName = localName(other);
          if (otherName === "ExtendedKeyUsage") {
            (criteria.extendedKeyUsage ??= []).push(collectIdentifiers(other, ["Identifier"]));
          } else if (otherName === "CertSubjectDNAttribute") {
            (criteria.subjectDnAttributes ??= []).push(
              collectIdentifiers(other, ["AttributeOID", "Identifier"]),
            );
          } else {
            criteria.unsupported = true;
          }
        }
        break;
      case "Description":
        break;
      default:
        criteria.unsupported = true;
    }
  }

  return criteria;
}

export interface ServiceInformationExtensions {
  additionalServiceInfo: string[];
  qualifications: QualificationElement[];
}

/**
 * Read AdditionalServiceInformation URIs (as suffixes, e.g. "ForeSignatures")
 * and Qualifications elements from a ServiceInformation or
 * ServiceHistoryInstance element.
 */
export function parseServiceInformationExtensions(
  container: Element | null,
): ServiceInformationExtensions {
  const result: ServiceInformationExtensions = {
    additionalServiceInfo: [],
    qualifications: [],
  };
  const extensions = getChildElement(container, "ServiceInformationExtensions");

  for (const extension of getChildElements(extensions, "Extension")) {
    for (const child of childElements(extension)) {
      const name = localName(child);
      if (name === "AdditionalServiceInformation") {
        const uri = text(getChildElement(child, "URI"));
        if (uri) {
          result.additionalServiceInfo.push(getUriSuffix(uri));
        }
      } else if (name === "Qualifications") {
        for (const element of getChildElements(child, "QualificationElement")) {
          const qualifiers = getChildElements(getChildElement(element, "Qualifiers"), "Qualifier")
            .map((qualifier) => getUriSuffix(qualifier.getAttribute("uri") || ""))
            .filter(Boolean);
          const criteriaElement = getChildElement(element, "CriteriaList");
          if (qualifiers.length === 0 || !criteriaElement) {
            continue;
          }
          result.qualifications.push({
            qualifiers: [...new Set(qualifiers)].sort(),
            criteria: parseCriteriaList(criteriaElement),
          });
        }
      }
    }
  }

  return result;
}

export function getAdditionalServiceInfoMask(additionalServiceInfo: string[] = []): number {
  let mask = 0;
  for (const info of additionalServiceInfo) {
    const normalized = info.toLowerCase();
    if (normalized === "foresignatures") mask |= ASI_FOR_ESIGNATURES;
    else if (normalized === "foreseals") mask |= ASI_FOR_ESEALS;
    else if (normalized === "forwebsiteauthentication") mask |= ASI_FOR_WEBSITE_AUTHENTICATION;
  }
  return mask;
}
