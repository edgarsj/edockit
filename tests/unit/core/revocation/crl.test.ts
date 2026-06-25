import { readFileSync } from "fs";
import { join } from "path";
import { parseCRL, isSerialInCRL } from "../../../../src/core/revocation/crl";

const lvCrlPath = join(__dirname, "../../../fixtures/crl/LV_eID_ICA_2021.crl");

function readArrayBuffer(path: string): ArrayBuffer {
  const buf = readFileSync(path);
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

describe("parseCRL with national-scale CRLs", () => {
  it("parses a CRL that exceeds the asn1js default node cap (>10k nodes)", () => {
    // The LV eID ICA 2021 CRL has ~13k revoked entries, far more than asn1js's
    // DEFAULT_MAX_NODES (10000) DoS guard. parseCRL must not return null for it.
    const der = readArrayBuffer(lvCrlPath);

    const crl = parseCRL(der);

    expect(crl).not.toBeNull();
    expect(crl!.entries.length).toBeGreaterThan(10000);
  });

  it("exposes usable entries after parsing a large CRL", () => {
    const der = readArrayBuffer(lvCrlPath);

    const crl = parseCRL(der);

    // A serial known to be present in this CRL snapshot.
    const knownRevoked = isSerialInCRL(crl!, "1765cd7d4018b7be662ce1abb2b97197");
    expect(knownRevoked.isRevoked).toBe(true);
    expect(knownRevoked.revokedAt).toBeInstanceOf(Date);
  });
});
