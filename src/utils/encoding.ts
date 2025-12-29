/**
 * Cross-platform encoding utilities
 */

/**
 * Convert ArrayBuffer to base64 string (cross-platform)
 * Works in both browser and Node.js environments
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
