import {
  BasicConstraintsExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509CertificateGenerator,
} from "@peculiar/x509";
import { parseLotlPointers, parseTrustedList } from "../../../../src/core/trustedlist/extract";
import {
  normalizeDistinguishedName,
  normalizeKeyIdentifier,
} from "../../../../src/core/trustedlist/normalize";
import { TrustedListSource } from "../../../../src/core/trustedlist/types";

const SOURCE: TrustedListSource = {
  id: "eu",
  label: "EU LOTL",
  lotlUrl: "https://example.test/eu-lotl.xml",
};

async function createCertificateData(subjectName: string): Promise<{
  certificateBase64: string;
  skiBase64: string;
  skiHex: string;
  subjectDn: string;
}> {
  const keys = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );

  const subjectKeyIdentifierExtension = await SubjectKeyIdentifierExtension.create(keys.publicKey);
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: subjectName,
    notBefore: new Date("2020-01-01T00:00:00Z"),
    notAfter: new Date("2030-01-01T00:00:00Z"),
    keys,
    signingAlgorithm: {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    extensions: [subjectKeyIdentifierExtension, new BasicConstraintsExtension(true, 0, true)],
  });

  const parsedCertificate = new X509Certificate(certificate.toString("pem"));
  const skiHex = normalizeKeyIdentifier(subjectKeyIdentifierExtension.keyId);

  if (!skiHex) {
    throw new Error("Failed to compute subject key identifier");
  }

  return {
    certificateBase64: certificate.toString("base64"),
    skiBase64: Buffer.from(skiHex, "hex").toString("base64"),
    skiHex,
    subjectDn: normalizeDistinguishedName(parsedCertificate.subject),
  };
}

describe("trusted-list extraction", () => {
  it("keeps XML-bearing LOTL pointers and skips obvious human-facing URLs", () => {
    const xml = `
      <TrustServiceStatusList>
        <PointersToOtherTSL>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/lv.xml</TSLLocation>
            <SchemeTerritory>LV</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/ua.xtsl</TSLLocation>
            <SchemeTerritory>UA</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/tsl/endpoint</TSLLocation>
            <SchemeTerritory>EE</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/guide.html</TSLLocation>
            <SchemeTerritory>LT</SchemeTerritory>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://example.test/spec.pdf</TSLLocation>
            <SchemeTerritory>PL</SchemeTerritory>
          </OtherTSLPointer>
        </PointersToOtherTSL>
      </TrustServiceStatusList>
    `;

    const pointers = parseLotlPointers(xml, SOURCE);

    expect(pointers).toEqual([
      {
        url: "https://example.test/lv.xml",
        territory: "LV",
        source: SOURCE,
      },
      {
        url: "https://example.test/ua.xtsl",
        territory: "UA",
        source: SOURCE,
      },
      {
        url: "https://example.test/tsl/endpoint",
        territory: "EE",
        source: SOURCE,
      },
    ]);
  });

  it("extracts service identities and converts status snapshots into history periods", async () => {
    const { certificateBase64 } = await createCertificateData("CN=LVRTC Root,O=Example,C=LV");
    const xml = `
      <TrustServiceStatusList>
        <SchemeInformation>
          <SchemeTerritory>LV</SchemeTerritory>
        </SchemeInformation>
        <TrustServiceProviderList>
          <TrustServiceProvider>
            <TSPInformation>
              <TSPName>
                <Name xml:lang="en">LVRTC</Name>
              </TSPName>
            </TSPInformation>
            <TSPServices>
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                  <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                  <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
                  <ServiceDigitalIdentity>
                    <DigitalId>
                      <X509Certificate>${certificateBase64}</X509Certificate>
                    </DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
                <ServiceHistory>
                  <ServiceHistoryInstance>
                    <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
                    <StatusStartingTime>2023-01-01T00:00:00Z</StatusStartingTime>
                    <ServiceDigitalIdentity>
                      <DigitalId>
                        <X509Certificate>${certificateBase64}</X509Certificate>
                      </DigitalId>
                    </ServiceDigitalIdentity>
                  </ServiceHistoryInstance>
                </ServiceHistory>
              </TSPService>
            </TSPServices>
          </TrustServiceProvider>
        </TrustServiceProviderList>
      </TrustServiceStatusList>
    `;

    const services = await parseTrustedList(xml, { source: SOURCE });

    expect(services).toHaveLength(1);
    expect(services[0].country).toBe("LV");
    expect(services[0].tspName).toBe("LVRTC");
    expect(services[0].serviceType).toBe("CA/QC");
    expect(services[0].spkiSha256Hex).toMatch(/^[a-f0-9]{64}$/);
    expect(services[0].history).toEqual([
      {
        status: "withdrawn",
        from: "2023-01-01T00:00:00Z",
        to: "2024-01-01T00:00:00Z",
      },
      {
        status: "granted",
        from: "2024-01-01T00:00:00Z",
        to: null,
      },
    ]);
  });

  it("merges certificate-backed and certless history snapshots from Ireland-style TSL entries", async () => {
    const { certificateBase64, skiBase64, skiHex, subjectDn } = await createCertificateData(
      "CN=Post.Trust Root CA,OU=Post.Trust Ltd.,O=An Post,C=IE",
    );
    const xml = `
      <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ns5="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#">
        <SchemeInformation>
          <SchemeTerritory>IE</SchemeTerritory>
        </SchemeInformation>
        <TrustServiceProviderList>
          <TrustServiceProvider>
            <TSPInformation>
              <TSPName>
                <Name xml:lang="en">Post.Trust Ltd</Name>
              </TSPName>
            </TSPInformation>
            <TSPServices>
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                  <ServiceDigitalIdentity>
                    <DigitalId>
                      <X509Certificate>${certificateBase64}</X509Certificate>
                    </DigitalId>
                  </ServiceDigitalIdentity>
                  <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
                  <StatusStartingTime>2019-01-25T00:00:00Z</StatusStartingTime>
                </ServiceInformation>
                <ServiceHistory>
                  <ServiceHistoryInstance>
                    <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                    <ServiceDigitalIdentity>
                      <DigitalId>
                        <X509SubjectName>${subjectDn.replace(/,/g, ", ")}</X509SubjectName>
                      </DigitalId>
                      <DigitalId>
                        <X509SKI>${skiBase64}</X509SKI>
                      </DigitalId>
                    </ServiceDigitalIdentity>
                    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                    <StatusStartingTime>2016-06-30T22:00:00Z</StatusStartingTime>
                    <ServiceInformationExtensions>
                      <Extension Critical="false">
                        <ns5:Qualifications />
                      </Extension>
                    </ServiceInformationExtensions>
                  </ServiceHistoryInstance>
                </ServiceHistory>
              </TSPService>
            </TSPServices>
          </TrustServiceProvider>
        </TrustServiceProviderList>
      </TrustServiceStatusList>
    `;

    const services = await parseTrustedList(xml, { source: SOURCE });

    expect(services).toHaveLength(1);
    expect(services[0].country).toBe("IE");
    expect(services[0].tspName).toBe("Post.Trust Ltd");
    expect(services[0].subjectDn).toBe(subjectDn);
    expect(services[0].skiHex).toBe(skiHex);
    expect(services[0].spkiSha256Hex).toMatch(/^[a-f0-9]{64}$/);
    expect(services[0].history).toEqual([
      {
        status: "granted",
        from: "2016-06-30T22:00:00Z",
        to: "2019-01-25T00:00:00Z",
      },
      {
        status: "withdrawn",
        from: "2019-01-25T00:00:00Z",
        to: null,
      },
    ]);
  });
});
