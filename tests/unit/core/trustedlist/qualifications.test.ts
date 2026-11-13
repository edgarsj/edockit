import { parseTrustedList } from "../../../../src/core/trustedlist/extract";
import {
  buildCompactTrustedListBundle,
  buildTrustedListData,
  mergeForwardUnreachableTerritories,
} from "../../../../src/core/trustedlist/loader";
import { matchTrustListQuery } from "../../../../src/core/trustedlist/matcher";
import {
  getSpkiKey,
  isTrustedServiceStatus,
  hexToBase64Url,
} from "../../../../src/core/trustedlist/normalize";
import type {
  CompactTrustedListBundle,
  TrustedListSource,
  TrustedService,
} from "../../../../src/core/trustedlist/types";
import { renderTrustedListTypeScriptModule } from "../../../../scripts/lib/trusted-list-builder";

const SOURCE: TrustedListSource = {
  id: "eu",
  label: "EU LOTL",
  lotlUrl: "https://example.test/eu-lotl.xml",
};

const SPKI_HEX = "aa".repeat(32);
const unix = (iso: string) => Math.floor(Date.parse(iso) / 1000);

const TSL = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"
  xmlns:ns3="http://uri.etsi.org/02231/v2/additionaltypes#"
  xmlns:ns4="http://uri.etsi.org/01903/v1.3.2#"
  xmlns:ns5="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#">
  <SchemeInformation><SchemeTerritory>LV</SchemeTerritory></SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation><TSPName><Name xml:lang="en">Example TSP</Name></TSPName></TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceDigitalIdentity>
              <DigitalId><X509SubjectName>CN=Example CA, C=LV</X509SubjectName></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2016-07-01T00:00:00Z</StatusStartingTime>
            <ServiceInformationExtensions>
              <Extension Critical="true">
                <ns5:Qualifications>
                  <ns5:QualificationElement>
                    <ns5:Qualifiers>
                      <ns5:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/>
                    </ns5:Qualifiers>
                    <ns5:CriteriaList assert="atLeastOne">
                      <ns5:KeyUsage>
                        <ns5:KeyUsageBit name="nonRepudiation">true</ns5:KeyUsageBit>
                      </ns5:KeyUsage>
                      <ns5:PolicySet>
                        <ns5:PolicyIdentifier>
                          <ns4:Identifier Qualifier="OIDAsURN">urn:oid:1.2.3.4</ns4:Identifier>
                        </ns5:PolicyIdentifier>
                      </ns5:PolicySet>
                    </ns5:CriteriaList>
                  </ns5:QualificationElement>
                  <ns5:QualificationElement>
                    <ns5:Qualifiers>
                      <ns5:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal"/>
                    </ns5:Qualifiers>
                    <ns5:CriteriaList assert="all">
                      <ns5:CriteriaList assert="none">
                        <ns5:KeyUsage>
                          <ns5:KeyUsageBit name="keyCertSign">true</ns5:KeyUsageBit>
                        </ns5:KeyUsage>
                      </ns5:CriteriaList>
                      <ns5:otherCriteriaList>
                        <ns3:ExtendedKeyUsage>
                          <ns3:KeyPurposeId><ns4:Identifier>1.3.6.1.5.5.7.3.4</ns4:Identifier></ns3:KeyPurposeId>
                        </ns3:ExtendedKeyUsage>
                        <ns3:CertSubjectDNAttribute>
                          <ns3:AttributeOID><ns4:Identifier>2.5.4.97</ns4:Identifier></ns3:AttributeOID>
                        </ns3:CertSubjectDNAttribute>
                      </ns5:otherCriteriaList>
                    </ns5:CriteriaList>
                  </ns5:QualificationElement>
                </ns5:Qualifications>
              </Extension>
              <Extension Critical="true">
                <AdditionalServiceInformation>
                  <URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI>
                </AdditionalServiceInformation>
              </Extension>
              <Extension Critical="true">
                <AdditionalServiceInformation>
                  <URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals</URI>
                </AdditionalServiceInformation>
              </Extension>
            </ServiceInformationExtensions>
          </ServiceInformation>
          <ServiceHistory>
            <ServiceHistoryInstance>
              <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
              <ServiceDigitalIdentity>
                <DigitalId><X509SubjectName>CN=Example CA, C=LV</X509SubjectName></DigitalId>
              </ServiceDigitalIdentity>
              <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision</ServiceStatus>
              <StatusStartingTime>2012-01-01T00:00:00Z</StatusStartingTime>
            </ServiceHistoryInstance>
          </ServiceHistory>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`;

describe("trusted-list qualification data", () => {
  it("extracts additional service information and qualifications per history period", async () => {
    const [service] = await parseTrustedList(TSL, { source: SOURCE });

    expect(service.history).toEqual([
      { status: "undersupervision", from: "2012-01-01T00:00:00Z", to: "2016-07-01T00:00:00Z" },
      {
        status: "granted",
        from: "2016-07-01T00:00:00Z",
        to: null,
        additionalServiceInfo: ["ForeSignatures", "ForeSeals"],
        qualifications: [
          {
            qualifiers: ["QCWithQSCD"],
            criteria: {
              assert: "atLeastOne",
              keyUsage: [{ nonRepudiation: true }],
              policySets: [["1.2.3.4"]],
            },
          },
          {
            qualifiers: ["QCForESeal"],
            criteria: {
              assert: "all",
              criteriaLists: [{ assert: "none", keyUsage: [{ keyCertSign: true }] }],
              extendedKeyUsage: [["1.3.6.1.5.5.7.3.4"]],
              subjectDnAttributes: [["2.5.4.97"]],
            },
          },
        ],
      },
    ]);
  });

  it("treats pre-eIDAS supervision statuses as trusted", () => {
    expect(isTrustedServiceStatus("undersupervision")).toBe(true);
    expect(isTrustedServiceStatus("supervisionincessation")).toBe(true);
    expect(isTrustedServiceStatus("supervisionceased")).toBe(false);
  });

  it("round-trips qualification periods through a version 3 bundle", async () => {
    const [parsed] = await parseTrustedList(TSL, { source: SOURCE });
    const bundle = buildCompactTrustedListBundle(
      [{ ...parsed, spkiSha256Hex: SPKI_HEX }],
      [SOURCE],
      "2026-03-14T00:00:00Z",
    );

    expect(bundle.v).toBe(3);
    expect(bundle.quals).toHaveLength(2);
    expect(bundle.services[0][0]).toBe(getSpkiKey(SPKI_HEX));
    expect(bundle.services[0][0]).toHaveLength(24);
    expect(bundle.services[0][1]).toBeNull();
    expect(bundle.services[0][5]).toEqual([[unix("2012-01-01T00:00:00Z"), null]]);
    expect(bundle.services[0][7]).toEqual([
      [unix("2012-01-01T00:00:00Z"), unix("2016-07-01T00:00:00Z"), 0],
      [unix("2016-07-01T00:00:00Z"), null, 3, [0, 1]],
    ]);

    const data = buildTrustedListData(JSON.parse(JSON.stringify(bundle)));
    const match = matchTrustListQuery(
      {
        purpose: "signature_issuer",
        subjectDn: "CN=Example CA,C=LV",
        spkiSha256Hex: SPKI_HEX,
        time: new Date("2025-01-01T00:00:00Z"),
      },
      data,
    );

    expect(match).toMatchObject({ found: true, confidence: "exact", trustedAtTime: true });
    expect(match.qualificationPeriods).toHaveLength(2);
    expect(match.qualificationPeriods?.[1]).toMatchObject({
      forESignatures: true,
      forESeals: true,
      forWebSiteAuthentication: false,
    });
    expect(match.qualificationPeriods?.[1].qualifications[0].qualifiers).toEqual(["QCWithQSCD"]);
  });

  it("merges adjacent periods with the same service information", () => {
    const service: TrustedService = {
      skiHex: null,
      spkiSha256Hex: SPKI_HEX,
      subjectDn: "CN=Example CA,C=LV",
      country: "LV",
      tspName: "Example TSP",
      serviceType: "CA/QC",
      source: "eu",
      sourceLabel: "EU LOTL",
      history: [
        {
          status: "granted",
          from: "2016-07-01T00:00:00Z",
          to: "2018-01-01T00:00:00Z",
          additionalServiceInfo: ["ForeSignatures"],
        },
        {
          status: "granted",
          from: "2018-01-01T00:00:00Z",
          to: "2020-01-01T00:00:00Z",
          additionalServiceInfo: ["ForeSignatures"],
        },
        { status: "withdrawn", from: "2020-01-01T00:00:00Z", to: null },
      ],
    };
    const bundle = buildCompactTrustedListBundle([service], [SOURCE], "2026-03-14T00:00:00Z");

    expect(bundle.services[0][7]).toEqual([
      [unix("2016-07-01T00:00:00Z"), unix("2020-01-01T00:00:00Z"), 1],
    ]);
  });

  it("matches full SPKI hashes in version 2 bundles without qualification data", () => {
    const v2: CompactTrustedListBundle = {
      v: 2,
      generatedAt: "2026-03-14T00:00:00Z",
      sources: [["eu", "EU LOTL", "https://example.test/eu-lotl.xml"]],
      dns: ["CN=Example CA, C=LV"],
      services: [[hexToBase64Url(SPKI_HEX), null, 0, "LV", 1, [[0, null]], 0]],
    };
    const match = matchTrustListQuery(
      {
        purpose: "signature_issuer",
        subjectDn: "CN=Example CA,C=LV",
        spkiSha256Hex: SPKI_HEX,
        time: new Date("2025-01-01T00:00:00Z"),
      },
      buildTrustedListData(v2),
    );

    expect(match).toMatchObject({ found: true, confidence: "exact" });
    expect(match.qualificationPeriods).toBeUndefined();
  });

  it("carries forward qualification data with remapped codebook indexes", async () => {
    const [parsed] = await parseTrustedList(TSL, { source: SOURCE });
    const previous = buildCompactTrustedListBundle(
      [{ ...parsed, spkiSha256Hex: SPKI_HEX }],
      [SOURCE],
      "2026-01-01T00:00:00Z",
    );
    const fresh = buildCompactTrustedListBundle(
      [
        {
          skiHex: null,
          spkiSha256Hex: "bb".repeat(32),
          subjectDn: "CN=Other CA,C=EE",
          country: "EE",
          tspName: "Other",
          serviceType: "CA/QC",
          source: "eu",
          sourceLabel: "EU LOTL",
          history: [
            {
              status: "granted",
              from: "2020-01-01T00:00:00Z",
              to: null,
              qualifications: [
                {
                  qualifiers: ["QCForESeal"],
                  criteria: { assert: "all", subjectDnAttributes: [["2.5.4.97"]] },
                },
              ],
            },
          ],
        },
      ],
      [SOURCE],
      "2026-03-14T00:00:00Z",
    );

    const merged = mergeForwardUnreachableTerritories(fresh, previous, new Set(["LV"]));
    const data = buildTrustedListData(merged);
    const lv = data.services.find((service) => service.country === "LV")!;
    const ee = data.services.find((service) => service.country === "EE")!;

    expect(merged.quals).toHaveLength(3);
    expect(lv.qualificationPeriods?.[1].qualifications.map((q) => q.qualifiers)).toEqual([
      ["QCWithQSCD"],
      ["QCForESeal"],
    ]);
    expect(lv.qualificationPeriods?.[1].qualifications[1].criteria.assert).toBe("all");
    expect(lv.qualificationPeriods?.[1].qualifications[1].criteria.extendedKeyUsage).toEqual([
      ["1.3.6.1.5.5.7.3.4"],
    ]);
    expect(ee.qualificationPeriods?.[0].qualifications[0].qualifiers).toEqual(["QCForESeal"]);
  });

  it("renders the bundled module as a parsable JSON string", () => {
    const bundle: CompactTrustedListBundle = {
      v: 3,
      generatedAt: "2026-03-14T00:00:00Z",
      sources: [["eu", "EU 'LOTL'", "https://example.test/eu-lotl.xml"]],
      dns: ["CN=Back\\\\slash\\, Inc.,O=O'Brien   Ltd"],
      quals: [],
      services: [],
    };
    const module = renderTrustedListTypeScriptModule(bundle);
    const expression = module.match(/= (JSON\.parse\('.*'\));/s)?.[1];

    expect(expression).toBeDefined();
    expect(new Function(`return ${expression}`)()).toEqual(bundle);
  });
});
