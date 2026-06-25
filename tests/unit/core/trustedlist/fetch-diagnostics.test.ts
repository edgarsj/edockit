import { X509CertificateGenerator } from "@peculiar/x509";
import {
  fetchTrustedListBundleWithDiagnostics,
  type TrustedListSource,
} from "../../../../src/core/trustedlist";

const SOURCE: TrustedListSource = {
  id: "eu",
  label: "EU LOTL",
  lotlUrl: "https://example.test/lotl.xml",
};

async function createCertificateBase64(): Promise<string> {
  const keys = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=LV Test CA,O=Example,C=LV",
    notBefore: new Date("2020-01-01T00:00:00Z"),
    notAfter: new Date("2030-01-01T00:00:00Z"),
    keys,
    signingAlgorithm: {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
  });
  return certificate.toString("base64");
}

describe("trusted-list fetch diagnostics", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("reports only territories whose advertised endpoints all failed", async () => {
    const certificateBase64 = await createCertificateBase64();
    const lotlXml = `
      <TrustServiceStatusList>
        <PointersToOtherTSL>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/lv.xml</TSLLocation>
            <SchemeTerritory>LV</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/ee-primary.xml</TSLLocation>
            <SchemeTerritory>EE</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/ee-secondary.xml</TSLLocation>
            <SchemeTerritory>EE</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/lt.xml</TSLLocation>
            <SchemeTerritory>LT</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/pl.xml</TSLLocation>
            <SchemeTerritory>PL</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/fi.xml</TSLLocation>
            <SchemeTerritory>FI</SchemeTerritory>
          </OtherTSLPointer>
        </PointersToOtherTSL>
      </TrustServiceStatusList>
    `;
    const lvTslXml = `
      <TrustServiceStatusList>
        <SchemeInformation>
          <SchemeTerritory>LV</SchemeTerritory>
        </SchemeInformation>
        <TrustServiceProviderList>
          <TrustServiceProvider>
            <TSPInformation>
              <TSPName><Name xml:lang="en">LV Test</Name></TSPName>
            </TSPInformation>
            <TSPServices>
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                  <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                  <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>${certificateBase64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TSPServices>
          </TrustServiceProvider>
        </TrustServiceProviderList>
      </TrustServiceStatusList>
    `;

    globalThis.fetch = jest.fn(async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      if (url === SOURCE.lotlUrl) {
        return new Response(lotlXml, { status: 200 });
      }
      if (url.endsWith("/lv.xml")) {
        return new Response(lvTslXml, { status: 200 });
      }
      if (url.endsWith("/lt.xml")) {
        // A successful response with no services may represent a legitimate
        // removal; it must not be classified as unreachable.
        return new Response("<TrustServiceStatusList />", { status: 200 });
      }
      if (url.endsWith("/pl.xml")) {
        // HTTP 200 error pages are not successful TSL parses.
        return new Response("<html><body>temporary error</body></html>", { status: 200 });
      }
      if (url.endsWith("/fi.xml")) {
        // Malformed TSL XML must also count as an endpoint failure.
        return new Response("<TrustServiceStatusList><SchemeInformation>", { status: 200 });
      }
      if (url.endsWith("/ee-primary.xml")) {
        return new Response("unavailable", { status: 503 });
      }
      if (url.endsWith("/ee-secondary.xml")) {
        throw new Error("network unavailable");
      }
      throw new Error(`Unexpected URL: ${url}`);
    }) as typeof fetch;

    const result = await fetchTrustedListBundleWithDiagnostics([SOURCE]);

    expect(result.bundle.services.some((service) => service[3] === "LV")).toBe(true);
    expect(result.diagnostics.unreachableTerritories).toEqual(["EE", "FI", "PL"]);
  });
});
