import { SignatureInfo } from "../../../src/core/parser";
import { verifySignature } from "../../../src/core/verification";
import { checkCertificateValidity, parseCertificate } from "../../../src/core/certificate";
import { checkCertificateRevocation } from "../../../src/core/revocation/check";
import { verifyTimestamp } from "../../../src/core/timestamp/verify";
import { matchCertificateIssuerToTrustedList } from "../../../src/core/trustedlist/matcher";
import { TrustedListData } from "../../../src/core/trustedlist/types";

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

jest.mock("../../../src/core/trustedlist/matcher", () => ({
  matchCertificateIssuerToTrustedList: jest.fn(),
}));

const mockCheckCertificateValidity = checkCertificateValidity as jest.MockedFunction<
  typeof checkCertificateValidity
>;
const mockParseCertificate = parseCertificate as jest.MockedFunction<typeof parseCertificate>;
const mockCheckCertificateRevocation = checkCertificateRevocation as jest.MockedFunction<
  typeof checkCertificateRevocation
>;
const mockVerifyTimestamp = verifyTimestamp as jest.MockedFunction<typeof verifyTimestamp>;
const mockMatchCertificateIssuerToTrustedList =
  matchCertificateIssuerToTrustedList as jest.MockedFunction<
    typeof matchCertificateIssuerToTrustedList
  >;

function createSignatureInfo(overrides: Partial<SignatureInfo> = {}): SignatureInfo {
  return {
    id: "sig-1",
    signingTime: new Date("2025-01-10T12:00:00Z"),
    certificate: "mock-certificate-data",
    certificatePEM: "-----BEGIN CERTIFICATE-----\nmock-certificate\n-----END CERTIFICATE-----",
    certificateChain: [
      "-----BEGIN CERTIFICATE-----\nmock-issuer-certificate\n-----END CERTIFICATE-----",
    ],
    signedChecksums: {},
    references: [],
    signatureTimestamp: "mock-timestamp-token",
    canonicalSignatureValue: "<ds:SignatureValue>abc</ds:SignatureValue>",
    ...overrides,
  };
}

function createTrustedListData(): TrustedListData {
  return {
    version: 1,
    generatedAt: "2026-03-14T00:00:00Z",
    sources: [],
    services: [],
    indexes: {
      bySki: new Map(),
      bySpkiSha256: new Map(),
      bySubjectDn: new Map(),
    },
  };
}

function getChecklistItem(result: Awaited<ReturnType<typeof verifySignature>>, check: string) {
  return result.checklist?.find((item) => item.check === check);
}

describe("Signature Verification", () => {
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
      },
    });

    mockCheckCertificateRevocation.mockResolvedValue({
      isValid: true,
      status: "good",
      method: "ocsp",
      checkedAt: new Date("2025-01-11T13:05:00Z"),
    });

    mockMatchCertificateIssuerToTrustedList.mockResolvedValue({
      found: true,
      trustedAtSigningTime: true,
      confidence: "aki_dn",
      country: "LV",
      tspName: "LVRTC",
      serviceType: "CA/QC",
      source: "eu",
      sourceLabel: "EU LOTL",
      detail: "LVRTC - EU LOTL (AKI/SKI + DN, trusted on signing date)",
    });
  });

  it("adds checklist items and trust-list matches to the verification result", async () => {
    const signatureInfo = createSignatureInfo();
    const trustedListData = createTrustedListData();
    const result = await verifySignature(signatureInfo, new Map(), {
      includeChecklist: true,
      verifySignatures: false,
      checkTrustedList: true,
      trustedListData,
      trustedListFetchOptions: {
        timeout: 2500,
        proxyUrl: "https://proxy.test/?url=",
      },
    });

    expect(result.isValid).toBe(true);
    expect(result.trustListMatch).toEqual({
      found: true,
      trustedAtSigningTime: true,
      confidence: "aki_dn",
      country: "LV",
      tspName: "LVRTC",
      serviceType: "CA/QC",
      source: "eu",
      sourceLabel: "EU LOTL",
      detail: "LVRTC - EU LOTL (AKI/SKI + DN, trusted on signing date)",
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
    expect(getChecklistItem(result, "certificate_not_revoked_at_signing_time")).toMatchObject({
      status: "pass",
    });
    expect(getChecklistItem(result, "issuer_trusted_at_signing_time")).toMatchObject({
      status: "pass",
      country: "LV",
      detail: "LVRTC - EU LOTL (AKI/SKI + DN, trusted on signing date)",
    });

    expect(mockMatchCertificateIssuerToTrustedList).toHaveBeenCalledWith(
      signatureInfo.certificatePEM,
      expect.objectContaining({
        certificateChain: signatureInfo.certificateChain,
        trustedListData,
        fetchOptions: {
          timeout: 2500,
          proxyUrl: "https://proxy.test/?url=",
        },
        signingTime: new Date("2025-01-11T13:00:00Z"),
      }),
    );
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

    const result = await verifySignature(createSignatureInfo(), new Map(), {
      includeChecklist: true,
      verifySignatures: false,
      checkRevocation: false,
    });

    expect(result.isValid).toBe(true);
    expect(getChecklistItem(result, "timestamp_valid")).toMatchObject({
      status: "fail",
      detail: "Could not verify timestamp covers signature (hash mismatch)",
    });
    expect(getChecklistItem(result, "certificate_not_revoked_at_signing_time")).toMatchObject({
      status: "skipped",
      detail: "Revocation check not enabled",
    });
    expect(getChecklistItem(result, "issuer_trusted_at_signing_time")).toMatchObject({
      status: "skipped",
      detail: "Trusted list check not enabled",
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

    const result = await verifySignature(createSignatureInfo(), new Map(), {
      includeChecklist: true,
      verifySignatures: false,
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
    mockMatchCertificateIssuerToTrustedList.mockResolvedValue({
      found: true,
      confidence: "dn_only",
      country: "LV",
      detail:
        "Only issuer DN matched trusted-list data; no AKI/SKI or issuer certificate match available",
    });

    const result = await verifySignature(createSignatureInfo(), new Map(), {
      includeChecklist: true,
      verifySignatures: false,
      checkRevocation: false,
      checkTrustedList: true,
    });

    expect(result.trustListMatch).toMatchObject({
      found: true,
      confidence: "dn_only",
    });
    expect(getChecklistItem(result, "issuer_trusted_at_signing_time")).toMatchObject({
      status: "indeterminate",
      country: "LV",
      detail:
        "Only issuer DN matched trusted-list data; no AKI/SKI or issuer certificate match available",
    });
  });
});
