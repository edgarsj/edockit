import type { TrustListQueryPurpose } from "./contract";
import type { TrustListPurposeMask } from "./types";

const RELEVANT_SERVICE_TYPES = [
  "CA/QC",
  "CA/PKC",
  "NationalRootCA-QC",
  "TSA/QTST",
  "TSA/TSS-QC",
  "MR-CA/QC",
  "MR-TSA/QTST",
] as const;

const SIGNATURE_ISSUER_PURPOSE_MASK = 1;
const TIMESTAMP_TSA_PURPOSE_MASK = 2;

const KNOWN_STATUS_SUFFIXES = [
  "granted",
  "recognisedatnationallevel",
  "accredited",
  "withdrawn",
  "deprecatedatnationallevel",
] as const;

const DN_ATTRIBUTE_ALIASES: Record<string, string> = {
  c: "C",
  cn: "CN",
  dnq: "DNQ",
  emailaddress: "E",
  e: "E",
  g: "GN",
  givenname: "GN",
  gn: "GN",
  l: "L",
  o: "O",
  organizationidentifier: "ORGANIZATIONIDENTIFIER",
  "2.5.4.97": "ORGANIZATIONIDENTIFIER",
  "oid.2.5.4.97": "ORGANIZATIONIDENTIFIER",
  ou: "OU",
  serialnumber: "SERIALNUMBER",
  sn: "SN",
  st: "ST",
  surname: "SN",
  street: "STREET",
  "2.5.4.5": "SERIALNUMBER",
};

function splitOnUnescaped(input: string, separator: string): string[] {
  const parts: string[] = [];
  let current = "";
  let escaped = false;

  for (const char of input) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === "\\") {
      current += char;
      escaped = true;
      continue;
    }

    if (char === separator) {
      parts.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  parts.push(current);
  return parts;
}

function normalizeDnAttributeKey(key: string): string {
  const trimmedKey = key.trim();
  const alias = DN_ATTRIBUTE_ALIASES[trimmedKey.toLowerCase()];
  return alias || trimmedKey.toUpperCase();
}

function normalizeDnAttributeValue(key: string, value: string): string {
  const normalized = value.trim().replace(/\s+/g, " ");
  if (key === "C") {
    return normalized.toUpperCase();
  }
  return normalized;
}

export function normalizeHex(input?: string | null): string | null {
  if (!input) {
    return null;
  }

  const normalized = input.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
  return normalized || null;
}

export function hexToBase64Url(input?: string | null): string | null {
  const normalized = normalizeHex(input);
  if (!normalized) {
    return null;
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }

  return bytesToBase64Url(bytes);
}

export function base64UrlToHex(input?: string | null): string | null {
  if (!input) {
    return null;
  }

  const bytes = decodeBase64Url(input.trim());
  return bytes ? bytesToHex(bytes) : null;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64url");
  }

  if (typeof btoa === "function") {
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  throw new Error("No base64url encoder available in this environment");
}

function decodeBase64(input: string): Uint8Array | null {
  const normalizedInput = input.replace(/\s+/g, "");

  try {
    if (typeof Buffer !== "undefined") {
      return Uint8Array.from(Buffer.from(normalizedInput, "base64"));
    }

    if (typeof atob === "function") {
      const decoded = atob(normalizedInput);
      return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    }
  } catch {
    return null;
  }

  return null;
}

function decodeBase64Url(input: string): Uint8Array | null {
  const normalizedInput = input.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (normalizedInput.length % 4 || 4)) % 4;
  return decodeBase64(normalizedInput + "=".repeat(paddingLength));
}

export function normalizeKeyIdentifier(
  input?: string | ArrayBuffer | ArrayBufferView | null,
): string | null {
  if (!input) {
    return null;
  }

  if (typeof input !== "string") {
    if (ArrayBuffer.isView(input)) {
      return bytesToHex(new Uint8Array(input.buffer, input.byteOffset, input.byteLength));
    }

    return bytesToHex(new Uint8Array(input));
  }

  const trimmedInput = input.trim();
  if (!trimmedInput) {
    return null;
  }

  const hexCandidate = normalizeHex(trimmedInput);
  const hexLikeInput = trimmedInput.replace(/[\s:-]+/g, "");
  // Prefer explicit hex-like inputs before attempting base64 decoding. Short values such as
  // "AABB" are syntactically valid in both encodings; treating even-length hex-safe input as
  // hex first preserves common SKI/AKI representations and makes the priority order explicit.
  if (hexCandidate && /^[a-fA-F0-9]+$/.test(hexLikeInput) && hexLikeInput.length % 2 === 0) {
    return hexCandidate;
  }

  if (
    /^[A-Za-z0-9+/=\s]+$/.test(trimmedInput) &&
    trimmedInput.replace(/\s+/g, "").length % 4 === 0
  ) {
    const decodedBytes = decodeBase64(trimmedInput);
    if (decodedBytes && decodedBytes.length > 0) {
      return bytesToHex(decodedBytes);
    }
  }

  return hexCandidate;
}

export function normalizeDistinguishedName(dn?: string | null): string {
  if (!dn) {
    return "";
  }

  const normalizedParts = splitOnUnescaped(dn, ",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const [rawKey, ...rawValueParts] = splitOnUnescaped(part, "=");
      if (!rawKey || rawValueParts.length === 0) {
        return part.replace(/\s+/g, " ");
      }

      const key = normalizeDnAttributeKey(rawKey);
      const value = normalizeDnAttributeValue(key, rawValueParts.join("="));
      return `${key}=${value}`;
    });

  return normalizedParts.sort((left, right) => left.localeCompare(right)).join(",");
}

export function isTrustedServiceStatus(status: string): boolean {
  const normalizedStatus = status.trim().toLowerCase();
  return (
    normalizedStatus === "granted" ||
    normalizedStatus === "recognisedatnationallevel" ||
    normalizedStatus === "accredited"
  );
}

export function getRelevantServiceType(uri?: string | null): string | null {
  if (!uri) {
    return null;
  }

  const normalizedUri = uri.trim().toLowerCase();
  const match = RELEVANT_SERVICE_TYPES.find((serviceType) =>
    normalizedUri.endsWith(serviceType.toLowerCase()),
  );

  return match || null;
}

export function getTrustListPurposeMaskForQueryPurpose(
  purpose: TrustListQueryPurpose,
): TrustListPurposeMask {
  return purpose === "signature_issuer"
    ? SIGNATURE_ISSUER_PURPOSE_MASK
    : TIMESTAMP_TSA_PURPOSE_MASK;
}

export function trustListPurposeMatchesMask(
  purpose: TrustListQueryPurpose,
  purposeMask: TrustListPurposeMask,
): boolean {
  return (getTrustListPurposeMaskForQueryPurpose(purpose) & purposeMask) !== 0;
}

export function getTrustListPurposeMaskForServiceType(
  serviceType: string,
): TrustListPurposeMask | null {
  if (serviceType === "CA/QC" || serviceType === "CA/PKC" || serviceType === "NationalRootCA-QC") {
    return SIGNATURE_ISSUER_PURPOSE_MASK;
  }

  if (serviceType === "TSA/QTST" || serviceType === "TSA/TSS-QC") {
    return TIMESTAMP_TSA_PURPOSE_MASK;
  }

  if (serviceType === "MR-CA/QC") {
    return SIGNATURE_ISSUER_PURPOSE_MASK;
  }

  if (serviceType === "MR-TSA/QTST") {
    return TIMESTAMP_TSA_PURPOSE_MASK;
  }

  return null;
}

export function getServiceStatusSuffix(uri?: string | null): string | null {
  if (!uri) {
    return null;
  }

  const normalizedUri = uri.trim().toLowerCase();
  const knownMatch = KNOWN_STATUS_SUFFIXES.find((status) => normalizedUri.endsWith(status));
  if (knownMatch) {
    return knownMatch;
  }

  const marker = "/svcstatus/";
  const markerIndex = normalizedUri.lastIndexOf(marker);
  if (markerIndex >= 0) {
    const suffix = normalizedUri.slice(markerIndex + marker.length).replace(/^\/+|\/+$/g, "");
    return suffix || null;
  }

  const hashIndex = normalizedUri.lastIndexOf("#");
  if (hashIndex >= 0) {
    const suffix = normalizedUri.slice(hashIndex + 1).replace(/^\/+|\/+$/g, "");
    return suffix || null;
  }

  const segments = normalizedUri.split("/").filter(Boolean);
  return segments.length > 0 ? segments[segments.length - 1] : null;
}

export function isLikelyXmlTslUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const pathname = parsed.pathname.toLowerCase();

    if (pathname.endsWith(".pdf") || pathname.endsWith(".html") || pathname.endsWith(".htm")) {
      return false;
    }

    return true;
  } catch {
    const normalizedUrl = url.trim().toLowerCase();
    return (
      normalizedUrl.length > 0 &&
      !normalizedUrl.endsWith(".pdf") &&
      !normalizedUrl.endsWith(".html") &&
      !normalizedUrl.endsWith(".htm")
    );
  }
}
