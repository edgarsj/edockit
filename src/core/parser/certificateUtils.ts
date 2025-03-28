// src/core/parser/certificateUtils.ts

/**
 * Format a certificate string as a proper PEM certificate
 * @param certBase64 Base64-encoded certificate
 * @returns Formatted PEM certificate
 */
export function formatPEM(certBase64?: string): string {
  if (!certBase64) return "";

  // Remove any whitespace from the base64 string
  const cleanBase64 = certBase64.replace(/\s+/g, "");

  // Split the base64 into lines of 64 characters
  const lines = [];
  for (let i = 0; i < cleanBase64.length; i += 64) {
    lines.push(cleanBase64.substring(i, i + 64));
  }

  // Format as PEM certificate
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}
