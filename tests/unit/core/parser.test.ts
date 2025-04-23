// tests/unit/core/parser.test.ts
import { __test__ } from "../../../src/core/parser/signatureParser";
import { querySelector, querySelectorAll } from "../../../src/utils/xmlParser";
import { CANONICALIZATION_METHODS } from "../../../src/core/canonicalization/XMLCanonicalizer";

const { parseSignatureElement } = __test__;

// maybe remove the serialization in implementation or test separately
global.XMLSerializer = jest.fn().mockImplementation(() => ({
  serializeToString: jest.fn().mockReturnValue("<ds:SignedInfo>mocked xml</ds:SignedInfo>"),
}));

// Mock the certificate module
jest.mock("../../../src/core/certificate", () => ({
  extractSignerInfo: jest.fn().mockReturnValue({
    commonName: "Test User",
    organization: "Test Org",
    country: "US",
    serialNumber: "12345",
    validFrom: new Date(),
    validTo: new Date(),
    issuer: {
      commonName: "Test CA",
      organization: "Test CA Org",
      country: "US",
    },
  }),
}));

// Mock X509Certificate
jest.mock("@peculiar/x509", () => ({
  X509Certificate: class MockX509Certificate {
    publicKey: any;

    constructor() {
      this.publicKey = {
        algorithm: {
          name: "RSASSA-PKCS1-v1_5",
        },
        rawData: new ArrayBuffer(0),
      };
    }

    // Add missing methods for X509Certificate
    exportAsPem() {
      return "-----BEGIN CERTIFICATE-----\nMockCertificateBase64==\n-----END CERTIFICATE-----";
    }
  },
}));

// Mock canonicalization methods
jest.mock("../../../src/core/canonicalization/XMLCanonicalizer", () => ({
  CANONICALIZATION_METHODS: {
    default: "http://www.w3.org/2001/10/xml-exc-c14n#",
  },
}));

// Mock the XMLParser utilities
jest.mock("../../../src/utils/xmlParser", () => ({
  createXMLParser: jest.fn(),
  querySelector: jest.fn(),
  querySelectorAll: jest.fn(),
  serializeToXML: jest.fn().mockReturnValue("<ds:SignedInfo>mocked xml</ds:SignedInfo>"),
}));

describe("Signature Parser", () => {
  beforeEach(() => {
    jest.clearAllMocks();

    // Create a map of selector patterns to responses
    const mockResponses = {
      SignedInfo: {
        nodeName: "ds:SignedInfo",
      },
      CanonicalizationMethod: {
        getAttribute: () => "http://www.w3.org/2001/10/xml-exc-c14n#",
      },
      SignatureMethod: {
        getAttribute: () => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      },
      SignatureValue: {
        textContent: "MockSignatureValueBase64==",
      },
      X509Certificate: {
        textContent: "MockCertificateBase64==",
      },
      SigningTime: {
        textContent: "2023-04-15T14:30:00Z",
      },
      DigestValue: {
        textContent: "mock-digest-value",
      },
      Reference: {
        getAttribute: (attr: string) => {
          if (attr === "URI") return "test.pdf";
          if (attr === "Type") return "";
          return "";
        },
        querySelector: jest.fn().mockImplementation((selector) => {
          if (selector.includes("DigestValue")) {
            return { textContent: "mock-digest-value" };
          }
          if (selector.includes("DigestMethod")) {
            return { getAttribute: () => "http://www.w3.org/2001/04/xmlenc#sha256" };
          }
          return null;
        }),
      },
    };

    // Setup mock for querySelector - no recursion
    (querySelector as jest.Mock).mockImplementation((element, selector) => {
      // Check each key pattern and return the corresponding mock
      for (const [pattern, response] of Object.entries(mockResponses)) {
        if (selector.includes(pattern)) {
          return response;
        }
      }
      return null;
    });

    // Setup mock for querySelectorAll
    (querySelectorAll as jest.Mock).mockImplementation((element, selector) => {
      if (selector.includes("Reference")) {
        return [
          {
            getAttribute: (attr: string) => {
              if (attr === "URI") return "test.pdf";
              if (attr === "Type") return "";
              return "";
            },
            querySelector: (sel: string) => {
              if (sel.includes("DigestValue")) {
                return { textContent: "mock-digest-value" };
              }
              if (sel.includes("DigestMethod")) {
                return { getAttribute: () => "http://www.w3.org/2001/04/xmlenc#sha256" };
              }
              return null;
            },
          },
        ];
      }

      return [];
    });
  });

  it("should extract data from signature element", () => {
    // Create a mock signature element and document
    const mockSignatureElement = {
      nodeName: "ds:Signature",
      getAttribute: jest.fn().mockReturnValue("test-sig-id"),
      // Add missing methods for element
      ownerDocument: {
        createNodeIterator: jest.fn(),
        evaluate: jest.fn(),
      },
    };

    const mockDocument = {
      documentElement: {
        nodeName: "root",
      },
      createNodeIterator: jest.fn(),
      evaluate: jest.fn(),
    };

    // Call the function with our mocked elements
    const result = parseSignatureElement(
      mockSignatureElement as unknown as Element,
      mockDocument as unknown as Document,
    );

    // Verify results
    expect(result.id).toBe("test-sig-id");
    expect(result.signingTime).toBeInstanceOf(Date);
    expect(result.certificate).toBe("MockCertificateBase64==");
    expect(result.certificatePEM).toContain("-----BEGIN CERTIFICATE-----");
    expect(result.signatureValue).toBe("MockSignatureValueBase64==");
    expect(result.algorithm).toBe("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    expect(result.signedInfoXml).toBe("<ds:SignedInfo>mocked xml</ds:SignedInfo>");
    // Verify references array
    expect(result.references).toContain("test.pdf");

    // Verify signedChecksums object
    expect(result.signedChecksums).toEqual({ "test.pdf": "mock-digest-value" });

    // Verify that querySelector was called with the right parameters
    expect(querySelector).toHaveBeenCalledWith(mockSignatureElement, "ds\\:SignedInfo, SignedInfo");
  });
});
