import type { SignatureInfo } from "../../../src/core/parser";
import { verifySignature } from "../../../src/core/verification";
import { checkCertificateValidity, parseCertificate } from "../../../src/core/certificate";
import { checkCertificateRevocation } from "../../../src/core/revocation/check";
import { verifyTimestamp } from "../../../src/core/timestamp/verify";
import {
  extractCertificateIdentityFromCertificate,
  extractIssuerIdentityFromCertificate,
} from "../../../src/core/trustedlist/identity";
import type { TrustListProvider } from "../../../src/core/trustedlist/contract";

jest.mock("@peculiar/x509", () => ({
  X509Certificate: class MockX509Certificate {
    notBefore = new Date("2024-01-01T00:00:00Z");
    notAfter = new Date("2027-01-01T00:00:00Z");
    subject = "CN=Signer,O=Example,C=LV";
    issuer = "CN=Issuer,O=Example,C=LV";
  },
}));

jest.mock("../../../src/core/certificate", () => ({
  checkCertificateValidity: jest.fn(),
  parseCertificate: jest.fn(),
}));

jest.mock("../../../src/core/revocation/check", () => ({
  checkCertificateRevocation: jest.fn(),
}));

jest.mock("../../../src/core/timestamp/verify", () => ({
  verifyTimestamp: jest.fn(),
}));

jest.mock("../../../src/core/trustedlist/identity", () => ({
  extractIssuerIdentityFromCertificate: jest.fn(),
  extractCertificateIdentityFromCertificate: jest.fn(),
}));

const mockCheckCertificateValidity = checkCertificateValidity as jest.MockedFunction<
  typeof checkCertificateValidity
>;
const mockParseCertificate = parseCertificate as jest.MockedFunction<typeof parseCertificate>;
const mockCheckCertificateRevocation = checkCertificateRevocation as jest.MockedFunction<
  typeof checkCertificateRevocation
>;
const mockVerifyTimestamp = verifyTimestamp as jest.MockedFunction<typeof verifyTimestamp>;
const mockExtractIssuerIdentityFromCertificate =
  extractIssuerIdentityFromCertificate as jest.MockedFunction<
    typeof extractIssuerIdentityFromCertificate
  >;
const mockExtractCertificateIdentityFromCertificate =
  extractCertificateIdentityFromCertificate as jest.MockedFunction<
    typeof extractCertificateIdentityFromCertificate
  >;

// SHA-256 of "hello"
const FILES = new Map([["doc.txt", new TextEncoder().encode("hello")]]);
const HELLO_SHA256 = "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";

function createSignatureInfo(overrides: Partial<SignatureInfo> = {}): SignatureInfo {
  return {
    id: "sig-1",
    signingTime: new Date("2025-01-10T12:00:00Z"),
    certificate: "mock-certificate-data",
    certificatePEM: "-----BEGIN CERTIFICATE-----\nmock-certificate\n-----END CERTIFICATE-----",
    certificateChain: [
      "-----BEGIN CERTIFICATE-----\nmock-issuer-certificate\n-----END CERTIFICATE-----",
    ],
    signedChecksums: { "doc.txt": HELLO_SHA256 },
    digestAlgorithms: { "doc.txt": "http://www.w3.org/2001/04/xmlenc#sha256" },
    references: ["doc.txt"],
    signatureTimestamp: "mock-timestamp-token",
    canonicalSignatureValue: "<ds:SignatureValue>abc</ds:SignatureValue>",
    ...overrides,
  };
}

function getChecklistItem(result: Awaited<ReturnType<typeof verifySignature>>, check: string) {
  return result.checklist?.find((item) => item.check === check);
}

describe("Signature Verification", () => {
  const mockTrustListProvider: jest.Mocked<TrustListProvider> = {
    match: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();

    mockCheckCertificateValidity.mockReturnValue({
      isValid: true,
    });

    mockParseCertificate.mockResolvedValue({
      subject: {
        commonName: "Test Signer",
      },
      validFrom: new Date("2024-01-01T00:00:00Z"),
      validTo: new Date("2027-01-01T00:00:00Z"),
      issuer: {
        commonName: "Test Issuer",
      },
      serialNumber: "1234",
    });

    mockVerifyTimestamp.mockResolvedValue({
      isValid: true,
      coversSignature: true,
      info: {
        genTime: new Date("2025-01-11T13:00:00Z"),
        policy: "1.2.3",
        serialNumber: "01",
        hashAlgorithm: "SHA-256",
        messageImprint: "abcd",
        tsaCertificate:
          "-----BEGIN CERTIFICATE-----\nmock-tsa-certificate\n-----END CERTIFICATE-----",
      },
    });

    mockCheckCertificateRevocation.mockResolvedValue({
      isValid: true,
      status: "good",
      method: "ocsp",
      checkedAt: new Date("2025-01-11T13:05:00Z"),
    });

    mockExtractIssuerIdentityFromCertificate.mockResolvedValue({
      issuerSubjectDn: "C=LV,CN=Issuer,O=Example",
      authorityKeyIdentifierHex: "deadbeef",
      issuerCertificate: {
        subjectDn: "C=LV,CN=Issuer,O=Example",
        spkiSha256Hex: "aa11",
      },
    });

    mockExtractCertificateIdentityFromCertificate.mockResolvedValue({
      subjectDn: "C=LV,CN=TSA,O=Example",
      subjectKeyIdentifierHex: "cafebabe",
      spkiSha256Hex: "bb22",
    });

    mockTrustListProvider.match.mockImplementation(async (query) =>
      query.purpose === "signature_issuer"
        ? {
            found: true,
            trustedAtTime: true,
            confidence: "exact",
            country: "LV",
            detail: "Trusted-list issuer match by SPKI, trusted at the requested time",
          }
        : {
            found: true,
            trustedAtTime: true,
            confidence: "exact",
            country: "LV",
            detail:
              "Trusted-list timestamp authority match by certificate SPKI, trusted at the requested time",
          },
    );
  });

  it("adds checklist items and trust-list matches to the verification result", async () => {
    const signatureInfo = createSignatureInfo();
    const result = await verifySignature(signatureInfo, FILES, {
      includeChecklist: true,
      verifySignatures: false,
      trustListProvider: mockTrustListProvider,
      trustedListFetchOptions: {
        timeout: 2500,
        proxyUrl: "https://proxy.test/?url=",
      },
    });

    expect(result.isValid).toBe(true);
    expect(result.status).toBe("VALID");
    expect(result.trustListMatch).toEqual({
      found: true,
      trustedAtTime: true,
      confidence: "exact",
      country: "LV",
      detail: "Trusted-list issuer match by SPKI, trusted at the requested time",
    });
    expect(result.timestampTrustListMatch).toEqual({
      found: true,
      trustedAtTime: true,
      confidence: "exact",
      country: "LV",
      detail:
        "Trusted-list timestamp authority match by certificate SPKI, trusted at the requested time",
    });

    expect(getChecklistItem(result, "document_integrity")).toMatchObject({
      status: "pass",
    });
    expect(getChecklistItem(result, "signature_valid")).toMatchObject({
      status: "skipped",
      detail: "Signature verification not enabled",
    });
    expect(getChecklistItem(result, "certificate_valid_at_signing_time")).toMatchObject({
      status: "pass",
    });
    expect(getChecklistItem(result, "timestamp_present")).toMatchObject({
      status: "pass",
    });
    expect(getChecklistItem(result, "timestamp_valid")).toMatchObject({
      status: "pass",
    });
    expect(getChecklistItem(result, "timestamp_authority_trusted_at_signing_time")).toMatchObject({
      status: "pass",
      country: "LV",
      detail:
        "Trusted-list timestamp authority match by certificate SPKI, trusted at the requested time",
    });
    expect(getChecklistItem(result, "certificate_not_revoked_at_signing_time")).toMatchObject({
      status: "pass",
    });
    expect(getChecklistItem(result, "issuer_trusted_at_signing_time")).toMatchObject({
      status: "pass",
      country: "LV",
      detail: "Trusted-list issuer match by SPKI, trusted at the requested time",
    });

    expect(mockExtractIssuerIdentityFromCertificate).toHaveBeenCalledWith(
      signatureInfo.certificatePEM,
      {
        certificateChain: signatureInfo.certificateChain,
        fetchOptions: {
          timeout: 2500,
          proxyUrl: "https://proxy.test/?url=",
        },
      },
    );
    expect(mockVerifyTimestamp).toHaveBeenCalledWith(
      "mock-timestamp-token",
      expect.objectContaining({ certificates: signatureInfo.certificateChain }),
    );
    expect(mockExtractCertificateIdentityFromCertificate).toHaveBeenCalledWith(
      "-----BEGIN CERTIFICATE-----\nmock-tsa-certificate\n-----END CERTIFICATE-----",
    );
    expect(mockTrustListProvider.match).toHaveBeenNthCalledWith(2, {
      purpose: "signature_issuer",
      subjectDn: "C=LV,CN=Issuer,O=Example",
      skiHex: "deadbeef",
      spkiSha256Hex: "aa11",
      time: new Date("2025-01-11T13:00:00Z"),
    });
    expect(mockTrustListProvider.match).toHaveBeenNthCalledWith(1, {
      purpose: "timestamp_tsa",
      subjectDn: "C=LV,CN=TSA,O=Example",
      skiHex: "cafebabe",
      spkiSha256Hex: "bb22",
      time: new Date("2025-01-11T13:00:00Z"),
    });
  });

  it("fails the timestamp checklist item when the token does not cover the signature", async () => {
    mockVerifyTimestamp.mockResolvedValue({
      isValid: true,
      coversSignature: false,
      reason: "Could not verify timestamp covers signature (hash mismatch)",
      info: {
        genTime: new Date("2025-01-11T13:00:00Z"),
        policy: "1.2.3",
        serialNumber: "01",
        hashAlgorithm: "SHA-256",
        messageImprint: "abcd",
      },
    });

    const result = await verifySignature(createSignatureInfo(), FILES, {
      includeChecklist: true,
      verifySignatures: false,
      checkRevocation: false,
    });

    expect(result.isValid).toBe(false);
    expect(result.status).toBe("INDETERMINATE");
    expect(getChecklistItem(result, "timestamp_valid")).toMatchObject({
      status: "fail",
      detail: "Could not verify timestamp covers signature (hash mismatch)",
    });
    expect(getChecklistItem(result, "certificate_not_revoked_at_signing_time")).toMatchObject({
      status: "skipped",
      detail: "Revocation check not enabled",
    });
    expect(getChecklistItem(result, "timestamp_authority_trusted_at_signing_time")).toMatchObject({
      status: "skipped",
      detail: "Trusted-list provider not configured",
    });
    expect(getChecklistItem(result, "issuer_trusted_at_signing_time")).toMatchObject({
      status: "skipped",
      detail: "Trusted-list provider not configured",
    });
  });

  it("marks document integrity as skipped when checksum verification is disabled", async () => {
    const result = await verifySignature(createSignatureInfo(), new Map(), {
      includeChecklist: true,
      verifyChecksums: false,
      verifySignatures: false,
      checkRevocation: false,
      trustListProvider: mockTrustListProvider,
    });

    expect(result.isValid).toBe(true);
    expect(getChecklistItem(result, "document_integrity")).toMatchObject({
      status: "skipped",
      detail: "Checksum verification not enabled",
    });
  });

  it("treats revocation after signing time as a checklist pass", async () => {
    mockCheckCertificateRevocation.mockResolvedValue({
      isValid: false,
      status: "revoked",
      method: "ocsp",
      reason: "Certificate revoked",
      revokedAt: new Date("2025-02-01T00:00:00Z"),
      checkedAt: new Date("2025-02-01T00:05:00Z"),
    });

    const result = await verifySignature(createSignatureInfo(), FILES, {
      includeChecklist: true,
      verifySignatures: false,
      trustListProvider: mockTrustListProvider,
    });

    expect(result.isValid).toBe(true);
    expect(result.certificate.revocation).toMatchObject({
      status: "revoked",
      isValid: true,
    });
    expect(getChecklistItem(result, "certificate_valid_at_signing_time")).toMatchObject({
      status: "pass",
    });
    expect(getChecklistItem(result, "certificate_not_revoked_at_signing_time")).toMatchObject({
      status: "pass",
      detail: expect.stringContaining("before revocation"),
    });
  });

  it("marks DN-only trusted-list matches as indeterminate in the checklist", async () => {
    mockTrustListProvider.match.mockImplementation(async (query) =>
      query.purpose === "signature_issuer"
        ? {
            found: true,
            trustedAtTime: true,
            confidence: "dn_only",
            country: "LV",
            detail:
              "Only issuer DN matched trusted-list data; no SKI or issuer certificate SPKI match available",
          }
        : {
            found: true,
            trustedAtTime: true,
            confidence: "exact",
            country: "LV",
            detail:
              "Trusted-list timestamp authority match by certificate SPKI, trusted at the requested time",
          },
    );

    const result = await verifySignature(createSignatureInfo(), FILES, {
      includeChecklist: true,
      verifySignatures: false,
      checkRevocation: false,
      trustListProvider: mockTrustListProvider,
    });

    expect(result.trustListMatch).toMatchObject({
      found: true,
      confidence: "dn_only",
      trustedAtTime: true,
    });
    expect(getChecklistItem(result, "issuer_trusted_at_signing_time")).toMatchObject({
      status: "indeterminate",
      country: "LV",
      detail:
        "Only issuer DN matched trusted-list data; no SKI or issuer certificate SPKI match available",
    });
  });

  it("allows DN-only trusted-list matches to pass when explicitly enabled", async () => {
    mockTrustListProvider.match.mockResolvedValue({
      found: true,
      trustedAtTime: true,
      confidence: "dn_only",
      country: "LV",
      detail:
        "Only issuer DN matched trusted-list data; no SKI or issuer certificate SPKI match available",
    });

    const result = await verifySignature(
      createSignatureInfo({ signatureTimestamp: undefined }),
      new Map(),
      {
        includeChecklist: true,
        verifySignatures: false,
        checkRevocation: false,
        trustListProvider: mockTrustListProvider,
        allowWeakDnOnlyTrustMatch: true,
      },
    );

    expect(getChecklistItem(result, "issuer_trusted_at_signing_time")).toMatchObject({
      status: "pass",
      country: "LV",
      detail:
        "Only issuer DN matched trusted-list data; no SKI or issuer certificate SPKI match available",
    });
  });
  describe("status rules", () => {
    const baseOptions = {
      verifySignatures: false,
      trustListProvider: mockTrustListProvider,
    };

    it("does not use the claimed signing time to accept a later revocation", async () => {
      mockCheckCertificateRevocation.mockResolvedValue({
        isValid: false,
        status: "revoked",
        method: "ocsp",
        revokedAt: new Date("2025-02-01T00:00:00Z"),
        checkedAt: new Date("2025-02-01T00:05:00Z"),
      });

      const result = await verifySignature(
        createSignatureInfo({ signatureTimestamp: undefined }),
        FILES,
        baseOptions,
      );

      expect(result.status).toBe("INVALID");
      expect(result.certificate.revocation?.isValid).toBe(false);
    });

    it("does not use a timestamp that does not cover the signature as proof of existence", async () => {
      mockVerifyTimestamp.mockResolvedValue({
        isValid: false,
        coversSignature: false,
        reason: "Could not verify timestamp covers signature (hash mismatch)",
        info: {
          genTime: new Date("2025-01-11T13:00:00Z"),
          policy: "1.2.3",
          serialNumber: "01",
          hashAlgorithm: "SHA-256",
          messageImprint: "abcd",
        },
      });
      mockCheckCertificateRevocation.mockResolvedValue({
        isValid: false,
        status: "revoked",
        method: "ocsp",
        revokedAt: new Date("2025-02-01T00:00:00Z"),
        checkedAt: new Date("2025-02-01T00:05:00Z"),
      });

      const result = await verifySignature(createSignatureInfo(), FILES, baseOptions);

      expect(result.status).toBe("INVALID");
    });

    it("is INDETERMINATE without a trusted-list provider", async () => {
      const result = await verifySignature(createSignatureInfo(), FILES, {
        verifySignatures: false,
      });

      expect(result.status).toBe("INDETERMINATE");
      expect(result.limitations).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "TRUST_NOT_CHECKED" })]),
      );
    });

    it("requires the issuer certificate to be verified against the trusted list", async () => {
      mockExtractIssuerIdentityFromCertificate.mockResolvedValue({
        issuerSubjectDn: "C=LV,CN=Issuer,O=Example",
        authorityKeyIdentifierHex: "deadbeef",
        issuerCertificate: null,
      });
      mockTrustListProvider.match.mockImplementation(async (query) => ({
        found: true,
        trustedAtTime: true,
        confidence: query.purpose === "signature_issuer" ? "ski_dn" : "exact",
        country: "LV",
      }));

      const result = await verifySignature(createSignatureInfo(), FILES, baseOptions);

      expect(result.status).toBe("INDETERMINATE");
      expect(result.limitations).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "ISSUER_NOT_VERIFIED" })]),
      );
    });

    it("is INVALID when the named issuer certificate did not sign the signer certificate", async () => {
      mockExtractIssuerIdentityFromCertificate.mockResolvedValue({
        issuerSubjectDn: "C=LV,CN=Issuer,O=Example",
        authorityKeyIdentifierHex: "deadbeef",
        issuerSignatureMismatch: true,
        issuerCertificate: null,
      });

      const result = await verifySignature(createSignatureInfo(), FILES, baseOptions);

      expect(result.status).toBe("INVALID");
    });

    it("is INDETERMINATE when revocation status is unknown", async () => {
      mockCheckCertificateRevocation.mockResolvedValue({
        isValid: false,
        status: "unknown",
        method: "ocsp",
        reason: "No response",
        checkedAt: new Date("2025-02-01T00:05:00Z"),
      });

      const result = await verifySignature(createSignatureInfo(), FILES, baseOptions);

      expect(result.status).toBe("INDETERMINATE");
      expect(result.limitations).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "REVOCATION_UNKNOWN" })]),
      );
    });

    it("does not use a timestamp from an untrusted authority", async () => {
      mockTrustListProvider.match.mockImplementation(async (query) =>
        query.purpose === "signature_issuer"
          ? { found: true, trustedAtTime: true, confidence: "exact", country: "LV" }
          : { found: false },
      );

      const result = await verifySignature(createSignatureInfo(), FILES, baseOptions);

      expect(result.status).toBe("INDETERMINATE");
      expect(result.limitations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ code: "TIMESTAMP_AUTHORITY_NOT_TRUSTED" }),
        ]),
      );
    });

    it("is INVALID when the signature covers no files", async () => {
      const result = await verifySignature(
        createSignatureInfo({ signedChecksums: {}, references: [] }),
        FILES,
        baseOptions,
      );

      expect(result.status).toBe("INVALID");
      expect(result.statusMessage).toBe("Signature does not cover any files");
    });
  });
});
