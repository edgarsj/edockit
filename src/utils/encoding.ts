/**
 * Cross-platform encoding utilities for ArrayBuffer/Base64/Hex conversions
 * Works in both browser and Node.js environments
 */

/**
 * Convert ArrayBuffer to base64 string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  if (typeof btoa === "function") {
    // Browser
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  // Node.js
  return Buffer.from(bytes).toString("base64");
}

/**
 * Convert base64 string to ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  if (typeof atob === "function") {
    // Browser
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
  // Node.js
  const buffer = Buffer.from(base64, "base64");
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

/**
 * Convert base64 string to Uint8Array
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

/**
 * Convert ArrayBuffer to hex string
 */
export function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert hex string to ArrayBuffer
 */
export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

/**
 * Format DER bytes as PEM certificate
 */
export function arrayBufferToPEM(buffer: ArrayBuffer, type: string = "CERTIFICATE"): string {
  const base64 = arrayBufferToBase64(buffer);
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${type}-----\n${lines.join("\n")}\n-----END ${type}-----`;
}
