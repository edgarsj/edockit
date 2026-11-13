import type { CertificateQualificationFacts, QcStatements } from "../../../src/core/qcStatements";
import {
  determineSignatureQualification,
  evaluateQualificationCriteria,
  qualificationCriteriaMatch,
} from "../../../src/core/qualification";
import type { TrustListMatch } from "../../../src/core/trustedlist/contract";
import type {
  QualificationElement,
  TrustedQualificationPeriod,
} from "../../../src/core/trustedlist/types";

const unix = (iso: string) => Math.floor(Date.parse(iso) / 1000);

function facts(
  overrides: Partial<CertificateQualificationFacts> = {},
): CertificateQualificationFacts {
  return {
    notBefore: new Date("2024-01-01T00:00:00Z"),
    qcStatements: statements(),
    policies: [],
    keyUsage: new Set(["nonRepudiation"]),
    extendedKeyUsage: [],
    subjectAttributeOids: new Set(["2.5.4.3", "2.5.4.6"]),
    ...overrides,
  };
}

function statements(overrides: Partial<QcStatements> = {}): QcStatements {
  return {
    qcCompliance: true,
    qcQSCD: true,
    qcTypes: ["esign"],
    statementIds: [],
    ...overrides,
  };
}

function period(overrides: Partial<TrustedQualificationPeriod> = {}): TrustedQualificationPeriod {
  return {
    fromUnix: unix("2016-07-01T00:00:00Z"),
    toUnix: null,
    forESignatures: true,
    forESeals: false,
    forWebSiteAuthentication: false,
    qualifications: [],
    ...overrides,
  };
}

function match(periods?: TrustedQualificationPeriod[], source = "eu"): TrustListMatch {
  return {
    found: true,
    trustedAtTime: true,
    confidence: "exact",
    country: "LV",
    source,
    ...(periods ? { qualificationPeriods: periods } : {}),
  };
}

const signingTime = new Date("2025-03-01T00:00:00Z");

const withQscdByKeyUsage: QualificationElement = {
  qualifiers: ["QCWithQSCD"],
  criteria: { assert: "atLeastOne", keyUsage: [{ nonRepudiation: true }] },
};

describe("qualificationCriteriaMatch", () => {
  it("evaluates key usage, policy sets and nested lists", () => {
    const certificate = facts({ policies: ["1.2.3"], extendedKeyUsage: ["1.3.6.1.5.5.7.3.4"] });

    expect(
      qualificationCriteriaMatch(
        { assert: "all", keyUsage: [{ nonRepudiation: true, digitalSignature: false }] },
        certificate,
      ),
    ).toBe(true);
    expect(
      qualificationCriteriaMatch(
        { assert: "all", keyUsage: [{ digitalSignature: true }] },
        certificate,
      ),
    ).toBe(false);
    expect(
      qualificationCriteriaMatch(
        { assert: "atLeastOne", policySets: [["9.9"], ["1.2.3"]] },
        certificate,
      ),
    ).toBe(true);
    expect(
      qualificationCriteriaMatch(
        {
          assert: "all",
          policySets: [["1.2.3"]],
          criteriaLists: [{ assert: "none", extendedKeyUsage: [["1.3.6.1.5.5.7.3.1"]] }],
        },
        certificate,
      ),
    ).toBe(true);
    expect(
      qualificationCriteriaMatch(
        { assert: "all", subjectDnAttributes: [["2.5.4.97"]] },
        certificate,
      ),
    ).toBe(false);
  });

  it("keeps criteria it cannot evaluate unknown, also under negation", () => {
    expect(evaluateQualificationCriteria({ assert: "none", unsupported: true }, facts())).toBe(
      undefined,
    );
    const negatedUnknown = {
      assert: "none" as const,
      criteriaLists: [{ assert: "all" as const, unsupported: true }],
    };
    expect(evaluateQualificationCriteria(negatedUnknown, facts())).toBeUndefined();
    expect(qualificationCriteriaMatch(negatedUnknown, facts())).toBe(false);

    // A known result still decides the list when the unknown part cannot change it
    expect(
      evaluateQualificationCriteria(
        {
          assert: "atLeastOne",
          keyUsage: [{ nonRepudiation: true }],
          criteriaLists: [{ assert: "all", unsupported: true }],
        },
        facts(),
      ),
    ).toBe(true);
    expect(
      evaluateQualificationCriteria(
        {
          assert: "all",
          keyUsage: [{ digitalSignature: true }],
          criteriaLists: [{ assert: "all", unsupported: true }],
        },
        facts(),
      ),
    ).toBe(false);
  });

  it("does not match key usage criteria when the certificate has no key usage", () => {
    expect(
      qualificationCriteriaMatch(
        { assert: "atLeastOne", keyUsage: [{ nonRepudiation: true }] },
        facts({ keyUsage: null }),
      ),
    ).toBe(false);
  });
});

describe("determineSignatureQualification", () => {
  it("classifies a qualified signature certificate with QSCD as QESig", () => {
    const result = determineSignatureQualification({
      facts: facts(),
      trustListMatch: match([period({ qualifications: [withQscdByKeyUsage] })]),
      signingTime,
    });

    expect(result).toMatchObject({
      level: "QESig",
      label: "Qualified electronic signature",
      qualifiedCertificate: true,
      certificateType: "esign",
      qscd: true,
      notes: [],
    });
  });

  it("classifies a qualified seal certificate without QSCD as AdESeal-QC", () => {
    const result = determineSignatureQualification({
      facts: facts({ qcStatements: statements({ qcTypes: ["eseal"], qcQSCD: false }) }),
      trustListMatch: match([period({ forESignatures: true, forESeals: true })]),
      signingTime,
    });

    expect(result.level).toBe("AdESeal-QC");
    expect(result.qscd).toBe(false);
  });

  it("lets trusted-list qualifiers override the certificate", () => {
    const noQscd = determineSignatureQualification({
      facts: facts(),
      trustListMatch: match([
        period({
          qualifications: [
            {
              qualifiers: ["QCNoQSCD"],
              criteria: { assert: "atLeastOne", keyUsage: [{ nonRepudiation: true }] },
            },
          ],
        }),
      ]),
      signingTime,
    });
    expect(noQscd.level).toBe("AdESig-QC");

    const statementFromList = determineSignatureQualification({
      facts: facts({ qcStatements: null }),
      trustListMatch: match([
        period({
          qualifications: [
            {
              qualifiers: ["QCStatement", "QCWithQSCD"],
              criteria: { assert: "atLeastOne", keyUsage: [{ nonRepudiation: true }] },
            },
          ],
        }),
      ]),
      signingTime,
    });
    expect(statementFromList.level).toBe("QESig");

    const notQualified = determineSignatureQualification({
      facts: facts(),
      trustListMatch: match([
        period({
          qualifications: [
            {
              qualifiers: ["NotQualified"],
              criteria: { assert: "atLeastOne", keyUsage: [{ nonRepudiation: true }] },
            },
          ],
        }),
      ]),
      signingTime,
    });
    expect(notQualified.level).toBe("AdESig");
    expect(notQualified.notes).toContain(
      "The trusted list marks this certificate as not qualified",
    );
  });

  it("is not qualified when the service is not granted for the certificate type", () => {
    const result = determineSignatureQualification({
      facts: facts({ qcStatements: statements({ qcTypes: ["eseal"] }) }),
      trustListMatch: match([period({ forESignatures: true, forESeals: false })]),
      signingTime,
    });

    expect(result.level).toBe("AdESeal");
    expect(result.qualifiedCertificate).toBe(false);
    expect(result.notes[0]).toContain("electronic seals");
  });

  it("requires a granted CA/QC period both at issuance and at signing time", () => {
    const withdrawnBeforeSigning = determineSignatureQualification({
      facts: facts(),
      trustListMatch: match([period({ toUnix: unix("2025-01-01T00:00:00Z") })]),
      signingTime,
    });
    expect(withdrawnBeforeSigning.level).toBe("AdESig");
    expect(withdrawnBeforeSigning.atIssuance?.qualified).toBe(true);
    expect(withdrawnBeforeSigning.atSigningTime?.qualified).toBe(false);

    const grantedAfterIssuance = determineSignatureQualification({
      facts: facts(),
      trustListMatch: match([period({ fromUnix: unix("2024-06-01T00:00:00Z") })]),
      signingTime,
    });
    expect(grantedAfterIssuance.level).toBe("AdESig");
  });

  it("does not guess the type of a non-qualified certificate without QcType", () => {
    const result = determineSignatureQualification({
      facts: facts({ qcStatements: null }),
      trustListMatch: match([period({ forESignatures: true, forESeals: true })]),
      signingTime,
    });

    expect(result.level).toBe("AdES");
    expect(result.certificateType).toBeUndefined();
  });

  it("does not treat a certificate under non-EU legislation as EU qualified", () => {
    const result = determineSignatureQualification({
      facts: facts({ qcStatements: statements({ qcCClegislation: ["CH"] }) }),
      trustListMatch: match([period()]),
      signingTime,
    });

    expect(result.qualifiedCertificate).toBe(false);
  });

  it("treats pre-eIDAS QCP+SSCD certificates as qualified with QSCD", () => {
    const result = determineSignatureQualification({
      facts: facts({
        notBefore: new Date("2014-01-01T00:00:00Z"),
        qcStatements: null,
        policies: ["0.4.0.1456.1.1"],
      }),
      trustListMatch: match([
        period({ fromUnix: unix("2010-01-01T00:00:00Z"), forESignatures: false }),
      ]),
      signingTime: new Date("2015-01-01T00:00:00Z"),
    });

    expect(result.level).toBe("QESig");
  });

  it("reports a website certificate as not qualified for signatures", () => {
    const result = determineSignatureQualification({
      facts: facts({ qcStatements: statements({ qcTypes: ["web"] }) }),
      trustListMatch: match([period({ forWebSiteAuthentication: true })]),
      signingTime,
    });

    expect(result.level).toBe("AdES");
    expect(result.notes.join(" ")).toContain("website authentication");
  });

  it("is indeterminate when qualifier criteria cannot be evaluated", () => {
    const result = determineSignatureQualification({
      facts: facts(),
      trustListMatch: match([
        period({
          qualifications: [
            {
              qualifiers: ["QCWithQSCD"],
              criteria: {
                assert: "none",
                criteriaLists: [{ assert: "all", unsupported: true }],
              },
            },
          ],
        }),
      ]),
      signingTime,
    });

    expect(result.level).toBe("INDETERMINATE");
    expect(result.notes).toEqual([
      "The trusted list uses qualification criteria that cannot be evaluated",
    ]);
  });

  it("is indeterminate without qualification data and not qualified for third-country lists", () => {
    expect(
      determineSignatureQualification({ facts: facts(), trustListMatch: match(), signingTime })
        .level,
    ).toBe("INDETERMINATE");

    const thirdCountry = determineSignatureQualification({
      facts: facts(),
      trustListMatch: match([period()], "ades"),
      signingTime,
    });
    expect(thirdCountry.level).toBe("AdESig");
    expect(thirdCountry.qualifiedCertificate).toBe(false);
  });
});
