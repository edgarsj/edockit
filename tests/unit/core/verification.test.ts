import { verifySignature } from "../../../src/core/verification";
import { SignatureInfo } from "../../../src/core/parser";
import { mock } from "node:test";

describe("Signature Verification", () => {
  it("should return a verification result", async () => {
    // Create a mock signature object
    const mockSignature: SignatureInfo = {
      id: "test-sig-id",
      signingTime: new Date("2023-04-15T14:30:00Z"),
      certificate: "mock-certificate-data",
      certificatePEM:
        "-----BEGIN CERTIFICATE-----\nmock-certificate-content\n-----END CERTIFICATE-----",
      signedChecksums: {
        "test.pdf": "mock-digest-value",
      },
      references: ["test.pdf"],
    };

    // Create a mock files map
    const mockFiles = new Map<string, Uint8Array>();
    mockFiles.set("test.pdf", new TextEncoder().encode("Mock PDF content"));

    const result = await verifySignature(mockSignature, mockFiles, {
      checkRevocation: false, // Disable for unit tests
    });

    // For now, just check the structure
    expect(result).toHaveProperty("isValid");
    expect(result).toHaveProperty("errors");
  });
});
