import { readFileSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../src/core/parser";

const sampleFilePath = join(__dirname, "../fixtures/valid_samples/SampleFile.edoc");

describe("Embedded XAdES RevocationValues extraction", () => {
  it("captures the embedded OCSP response from an LT/LTA signature", () => {
    const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
    const sig = container.signatures[0];

    expect(sig.revocationValues).toBeDefined();
    // SampleFile is an LTA signature: it embeds an OCSP response captured at
    // signing time inside xades:RevocationValues/xades:OCSPValues.
    expect(sig.revocationValues!.ocsp.length).toBeGreaterThanOrEqual(1);

    // The captured value is base64-encoded DER (an OCSP response is a SEQUENCE,
    // so the decoded bytes start with 0x30).
    const der = Buffer.from(sig.revocationValues!.ocsp[0], "base64");
    expect(der.length).toBeGreaterThan(0);
    expect(der[0]).toBe(0x30);
  });
});
