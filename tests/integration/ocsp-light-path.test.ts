import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "@peculiar/x509";
import { parseEdoc } from "../../src/core/parser";
import { verifySignature } from "../../src/core/verification";
import { createBundledTrustListProvider } from "../../src/core/trustedlist/bundled-provider";
import {
  checkCertificateRevocation,
  extractCRLUrls,
  extractCertsFromOCSPResponses,
} from "../../src/core/revocation";

const sampleFilePath = join(__dirname, "../fixtures/valid_samples/SampleFile.edoc");

// The signer's certificate chain is empty in this container, so OCSP normally can't
// build a request and the verifier falls back to downloading the full (~668 KB) CRL.
// The issuer certificate is, however, embedded in the signature's RevocationValues
// OCSP response. Using it lets the lightweight live OCSP query succeed instead.
//
// The "live" response in this test is the signature's own embedded OCSP response
// (produced 2025-03-19T16:59:29Z, nextUpdate 15 minutes later). OCSP responses are
// checked for freshness, so the clock is set to inside that validity window.
const OCSP_RESPONSE_VALID_AT = new Date("2025-03-19T17:05:00Z");

describe("light live OCSP path via issuer cert from embedded data", () => {
  beforeEach(() => {
    // Only Date is faked; real timers keep fetch timeouts working.
    jest.useFakeTimers({
      now: OCSP_RESPONSE_VALID_AT,
      doNotFake: [
        "hrtime",
        "nextTick",
        "performance",
        "queueMicrotask",
        "requestAnimationFrame",
        "cancelAnimationFrame",
        "requestIdleCallback",
        "cancelIdleCallback",
        "setImmediate",
        "clearImmediate",
        "setInterval",
        "clearInterval",
        "setTimeout",
        "clearTimeout",
      ],
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("answers revocation with a live OCSP query and does not download the signer CRL", async () => {
    const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
    const sig = container.signatures[0];
    const signer = new X509Certificate(sig.certificatePEM);
    const signerCrlUrls = extractCRLUrls(signer);
    const ocspResponseDer = Buffer.from(sig.revocationValues!.ocsp[0], "base64");

    const fetchedUrls: string[] = [];
    const fetchSpy = jest
      .spyOn(global, "fetch")
      .mockImplementation(async (input: any): Promise<Response> => {
        const url = String(input);
        fetchedUrls.push(url);
        if (url.includes("ocsp")) {
          // Simulate the live responder returning a current "good" status.
          return new Response(ocspResponseDer, { status: 200 });
        }
        // Everything else (CRLs, AIA caIssuers) is "unavailable" in this test.
        throw new Error(`unexpected fetch: ${url}`);
      });

    const result = await verifySignature(sig, container.files, {
      includeChecklist: true,
      trustListProvider: createBundledTrustListProvider(),
    });

    fetchSpy.mockRestore();

    // Revocation was answered by OCSP (the light path), not the CRL fallback.
    expect(result.certificate.revocation?.method).toBe("ocsp");
    expect(result.certificate.revocation?.status).toBe("good");

    // The large signer CRL was never downloaded.
    for (const crlUrl of signerCrlUrls) {
      expect(fetchedUrls).not.toContain(crlUrl);
    }
  });
});

describe("live OCSP answers must be current", () => {
  it("does not accept an expired OCSP response returned by the responder", async () => {
    const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
    const sig = container.signatures[0];
    const ocspResponseDer = Buffer.from(sig.revocationValues!.ocsp[0], "base64");

    const fetchSpy = jest
      .spyOn(global, "fetch")
      .mockImplementation(async (input: any): Promise<Response> => {
        if (String(input).includes("ocsp")) {
          // A correctly signed but long-expired response (nextUpdate in 2025).
          return new Response(ocspResponseDer, { status: 200 });
        }
        throw new Error(`unexpected fetch: ${String(input)}`);
      });

    const result = await checkCertificateRevocation(sig.certificatePEM, {
      certificateChain: extractCertsFromOCSPResponses(sig.revocationValues!.ocsp),
    });

    fetchSpy.mockRestore();

    expect(result.status).not.toBe("good");
    expect(result.isValid).toBe(false);
    expect(result.reason).toMatch(/stale/);
  });
});
