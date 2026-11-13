import { readFileSync } from "fs";
import { join } from "path";
import { unzipSync, zipSync } from "fflate";
import { parseEdoc, verifySignature } from "../../src";
import { createTrustListProvider } from "../../src/trusted-list";
import bundledTrustedListBundle from "../../src/data/trusted-list";

// Long-term validation from verified OCSP responses embedded in the signature,
// used when live revocation data cannot answer (here: live checks disabled).
const SAMPLES = join(__dirname, "../fixtures/valid_samples");
const trustListProvider = createTrustListProvider({ data: bundledTrustedListBundle });
const offlineRevocation = { ocspEnabled: false, crlEnabled: false };

function load(name: string) {
  return readFileSync(join(SAMPLES, name));
}

describe("embedded revocation data for long-term validation", () => {
  jest.setTimeout(30000);

  it.each(["terms_of_use_of_private_credit_cards_25052018_RUS.edoc", "SampleFile.edoc"])(
    "uses a verified embedded OCSP response for %s",
    async (name) => {
      const container = parseEdoc(load(name));
      const [signature] = container.signatures;

      const result = await verifySignature(signature, container.files, {
        trustListProvider,
        revocationOptions: offlineRevocation,
      });

      expect(result.status).toBe("VALID");
      expect(result.certificate.revocation).toMatchObject({
        status: "good",
        method: "ocsp",
        embedded: true,
      });
    },
  );

  it("does not use embedded OCSP responses without proof of existence", async () => {
    const files = unzipSync(load("terms_of_use_of_private_credit_cards_25052018_RUS.edoc"));
    const signaturePath = Object.keys(files).find((name) => name.includes("signatures"))!;
    const xml = new TextDecoder()
      .decode(files[signaturePath])
      .replace(/<xades:SignatureTimeStamp[\s\S]*?<\/xades:SignatureTimeStamp>/, "");
    files[signaturePath] = new TextEncoder().encode(xml);

    const container = parseEdoc(zipSync(files));
    const result = await verifySignature(container.signatures[0], container.files, {
      trustListProvider,
      revocationOptions: offlineRevocation,
    });

    expect(result.signature?.isValid).toBe(true);
    expect(result.status).toBe("INDETERMINATE");
    expect(result.certificate.revocation?.embedded).toBeUndefined();
  });
});
