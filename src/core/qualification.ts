import type { TrustListMatch } from "./trustedlist/contract";
import type { QualificationCriteriaList, TrustedQualificationPeriod } from "./trustedlist/types";
import {
  PRE_EIDAS_QC_POLICY_OIDS,
  PRE_EIDAS_QC_SSCD_POLICY_OID,
  type CertificateQualificationFacts,
  type QcType,
} from "./qcStatements";

/**
 * Qualification level of a signature, following the naming used by the EU
 * DSS validation reports:
 * - QESig / QESeal: qualified electronic signature / seal (qualified
 *   certificate and private key in a QSCD)
 * - AdESig-QC / AdESeal-QC: advanced signature / seal with a qualified
 *   certificate, key not in a QSCD
 * - AdESig / AdESeal / AdES: advanced signature / seal (type unknown) without
 *   a qualified certificate
 * - INDETERMINATE: qualification could not be determined
 */
export type SignatureQualificationLevel =
  "QESig" | "QESeal" | "AdESig-QC" | "AdESeal-QC" | "AdESig" | "AdESeal" | "AdES" | "INDETERMINATE";

export interface CertificateQualificationAtTime {
  time: Date;
  /** The certificate is an EU qualified certificate at this time */
  qualified: boolean;
  type?: QcType;
  /** The private key is in a QSCD at this time */
  qscd: boolean;
}

export interface SignatureQualification {
  level: SignatureQualificationLevel;
  /** English description of `level` */
  label: string;
  /** The signer certificate is an EU qualified certificate */
  qualifiedCertificate: boolean;
  /** Certificate purpose (from the certificate's QcType or the trusted list) */
  certificateType?: QcType;
  /** The private key is in a qualified signature/seal creation device */
  qscd: boolean;
  /** Qualification at certificate issuance (notBefore) */
  atIssuance?: CertificateQualificationAtTime;
  /** Qualification at the signing time used for validation */
  atSigningTime?: CertificateQualificationAtTime;
  /** Why the signature is not qualified or could not be classified */
  notes: string[];
}

/** eIDAS trust service provisions apply from this date */
export const EIDAS_EFFECTIVE_DATE = new Date("2016-07-01T00:00:00Z");

const LEVEL_LABELS: Record<SignatureQualificationLevel, string> = {
  QESig: "Qualified electronic signature",
  QESeal: "Qualified electronic seal",
  "AdESig-QC": "Advanced electronic signature with a qualified certificate",
  "AdESeal-QC": "Advanced electronic seal with a qualified certificate",
  AdESig: "Advanced electronic signature",
  AdESeal: "Advanced electronic seal",
  AdES: "Advanced electronic signature or seal",
  INDETERMINATE: "Qualification could not be determined",
};

const TYPE_LABELS: Record<QcType, string> = {
  esign: "electronic signatures",
  eseal: "electronic seals",
  web: "website authentication",
};

function allOf(values: string[], present: (value: string) => boolean): boolean {
  return values.every(present);
}

/**
 * Evaluate a trusted-list CriteriaList against a certificate (ETSI TS 119 612,
 * 5.5.9.2) with three-valued logic: `undefined` means the list contains a
 * criterion this library cannot evaluate and the outcome depends on it.
 */
export function evaluateQualificationCriteria(
  criteria: QualificationCriteriaList,
  facts: CertificateQualificationFacts,
): boolean | undefined {
  const results: Array<boolean | undefined> = [];
  if (criteria.unsupported) {
    results.push(undefined);
  }
  for (const bits of criteria.keyUsage ?? []) {
    const keyUsage = facts.keyUsage;
    results.push(
      keyUsage !== null &&
        Object.entries(bits).every(([bit, expected]) => keyUsage.has(bit) === expected),
    );
  }
  for (const policySet of criteria.policySets ?? []) {
    results.push(allOf(policySet, (oid) => facts.policies.includes(oid)));
  }
  for (const purposes of criteria.extendedKeyUsage ?? []) {
    results.push(allOf(purposes, (oid) => facts.extendedKeyUsage.includes(oid)));
  }
  for (const attributes of criteria.subjectDnAttributes ?? []) {
    results.push(allOf(attributes, (oid) => facts.subjectAttributeOids.has(oid)));
  }
  for (const nested of criteria.criteriaLists ?? []) {
    results.push(evaluateQualificationCriteria(nested, facts));
  }

  const anyTrue = results.some((result) => result === true);
  const anyFalse = results.some((result) => result === false);
  const anyUnknown = results.some((result) => result === undefined);

  switch (criteria.assert) {
    case "all":
      return anyFalse ? false : anyUnknown ? undefined : true;
    case "none":
      return anyTrue ? false : anyUnknown ? undefined : true;
    default:
      return anyTrue ? true : anyUnknown ? undefined : false;
  }
}

/** Whether a trusted-list CriteriaList definitely matches a certificate */
export function qualificationCriteriaMatch(
  criteria: QualificationCriteriaList,
  facts: CertificateQualificationFacts,
): boolean {
  return evaluateQualificationCriteria(criteria, facts) === true;
}

type QualificationAtTimeResult = CertificateQualificationAtTime & {
  note?: string;
  /** Qualifier criteria could not be evaluated, so the result is unknown */
  undeterminable?: boolean;
};

function isIssuedBeforeEidas(facts: CertificateQualificationFacts): boolean {
  return facts.notBefore.getTime() < EIDAS_EFFECTIVE_DATE.getTime();
}

function hasPolicy(facts: CertificateQualificationFacts, oids: readonly string[]): boolean {
  return facts.policies.some((policy) => oids.includes(policy));
}

/** Type claimed by the certificate alone, used when the trusted list says nothing */
function getCertificateType(
  facts: CertificateQualificationFacts,
  serviceTypes: Set<QcType>,
): QcType | undefined {
  const qcTypes = facts.qcStatements?.qcTypes ?? [];
  if (qcTypes.length === 1) {
    return qcTypes[0];
  }
  if (qcTypes.length > 1) {
    const allowed = qcTypes.filter((type) => serviceTypes.has(type));
    return allowed.length === 1 ? allowed[0] : undefined;
  }
  if (serviceTypes.size === 1) {
    return [...serviceTypes][0];
  }
  // A qualified certificate without QcType is for electronic signatures
  // (ETSI EN 319 412-5); pre-eIDAS qualified certificates were all for
  // signatures of natural persons.
  return "esign";
}

function evaluatePeriod(
  facts: CertificateQualificationFacts,
  period: TrustedQualificationPeriod,
  time: Date,
): QualificationAtTimeResult {
  const qualifiers = new Set<string>();
  for (const element of period.qualifications) {
    const applies = evaluateQualificationCriteria(element.criteria, facts);
    if (applies === undefined) {
      return {
        time,
        qualified: false,
        qscd: false,
        undeterminable: true,
        note: "The trusted list uses qualification criteria that cannot be evaluated",
      };
    }
    if (applies) {
      element.qualifiers.forEach((qualifier) => qualifiers.add(qualifier));
    }
  }

  const issuedBeforeEidas = isIssuedBeforeEidas(facts);
  const statements = facts.qcStatements;

  // Qualified certificate claim, possibly overridden by the trusted list
  let qualified =
    (statements?.qcCompliance === true && !statements.qcCClegislation) ||
    (issuedBeforeEidas && hasPolicy(facts, PRE_EIDAS_QC_POLICY_OIDS));
  if (qualifiers.has("QCStatement")) {
    qualified = true;
  }
  let note: string | undefined;
  if (qualifiers.has("NotQualified")) {
    qualified = false;
    note = "The trusted list marks this certificate as not qualified";
  } else if (!qualified) {
    note = "The certificate does not claim to be a qualified certificate";
  }

  // Type
  const serviceTypes = new Set<QcType>();
  if (period.forESignatures) serviceTypes.add("esign");
  if (period.forESeals) serviceTypes.add("eseal");
  if (period.forWebSiteAuthentication) serviceTypes.add("web");

  const listedTypes = new Set<QcType>();
  if (qualifiers.has("QCForESig")) listedTypes.add("esign");
  if (qualifiers.has("QCForESeal") || qualifiers.has("QCForLegalPerson")) listedTypes.add("eseal");
  if (qualifiers.has("QCForWSA")) listedTypes.add("web");

  let type: QcType | undefined;
  if (listedTypes.size === 1) {
    type = [...listedTypes][0];
  } else if (listedTypes.size === 0) {
    type = getCertificateType(facts, serviceTypes);
  }

  if (qualified && type === undefined) {
    note = "The certificate type (signature, seal or website) is ambiguous";
  }
  if (qualified && type && serviceTypes.size > 0 && !serviceTypes.has(type)) {
    qualified = false;
    note = `The issuing service is not qualified to issue certificates for ${TYPE_LABELS[type]}`;
  }

  // QSCD
  let qscd =
    statements?.qcQSCD === true ||
    (issuedBeforeEidas && hasPolicy(facts, [PRE_EIDAS_QC_SSCD_POLICY_OID]));
  if (
    qualifiers.has("QCWithQSCD") ||
    qualifiers.has("QCWithSSCD") ||
    qualifiers.has("QCQSCDManagedOnBehalf")
  ) {
    qscd = true;
  } else if (qualifiers.has("QCNoQSCD") || qualifiers.has("QCNoSSCD")) {
    qscd = false;
  }

  return { time, qualified, type, qscd: qualified && qscd, ...(note ? { note } : {}) };
}

function evaluateAtTime(
  facts: CertificateQualificationFacts,
  periods: TrustedQualificationPeriod[],
  time: Date,
): QualificationAtTimeResult {
  const unix = Math.floor(time.getTime() / 1000);
  const active = periods.filter(
    (period) => unix >= period.fromUnix && (period.toUnix === null || unix < period.toUnix),
  );

  if (active.length === 0) {
    return {
      time,
      qualified: false,
      type: getCertificateType(facts, new Set()),
      qscd: false,
      note: `The issuer was not a qualified certificate service (CA/QC, granted) on ${time.toISOString()}`,
    };
  }

  const results = active.map((period) => evaluatePeriod(facts, period, time));
  return (
    results.find((result) => result.undeterminable) ??
    results.find((result) => result.qualified && result.type) ??
    results[0]
  );
}

function nonQualifiedLevel(type: QcType | undefined): SignatureQualificationLevel {
  return type === "esign" ? "AdESig" : type === "eseal" ? "AdESeal" : "AdES";
}

function buildResult(
  level: SignatureQualificationLevel,
  fields: Omit<SignatureQualification, "level" | "label">,
): SignatureQualification {
  return { level, label: LEVEL_LABELS[level], ...fields };
}

function stripNote({
  note: _note,
  undeterminable: _undeterminable,
  ...rest
}: QualificationAtTimeResult): CertificateQualificationAtTime {
  return rest;
}

/**
 * Determine the qualification of a signature from its signer certificate and
 * the trusted-list match of the certificate's issuer (ETSI TS 119 615,
 * simplified): the certificate must be qualified both when it was issued and
 * at signing time, and the QSCD status is taken at signing time.
 *
 * The caller is responsible for only using this when the issuer was matched
 * exactly (`confidence: "exact"`) and verified to have signed the certificate.
 */
export function determineSignatureQualification(input: {
  facts: CertificateQualificationFacts;
  trustListMatch: TrustListMatch;
  signingTime: Date;
}): SignatureQualification {
  const { facts, trustListMatch, signingTime } = input;
  const claimedTypes = facts.qcStatements?.qcTypes ?? [];
  const claimedType = claimedTypes.length === 1 ? claimedTypes[0] : undefined;

  if (trustListMatch.source === "ades") {
    return buildResult(nonQualifiedLevel(claimedType), {
      qualifiedCertificate: false,
      ...(claimedType ? { certificateType: claimedType } : {}),
      qscd: false,
      notes: [
        "The issuer is listed in a third-country trusted list, which does not establish EU qualified status",
      ],
    });
  }

  const periods = trustListMatch.qualificationPeriods;
  if (!periods) {
    return buildResult("INDETERMINATE", {
      qualifiedCertificate: false,
      ...(claimedType ? { certificateType: claimedType } : {}),
      qscd: false,
      notes: ["The trusted-list data has no qualification information"],
    });
  }

  const atIssuance = evaluateAtTime(facts, periods, facts.notBefore);
  const atSigningTime = evaluateAtTime(facts, periods, signingTime);
  const notes = [...new Set([atIssuance.note, atSigningTime.note].filter(Boolean) as string[])];

  if (atIssuance.undeterminable || atSigningTime.undeterminable) {
    return buildResult("INDETERMINATE", {
      qualifiedCertificate: false,
      ...(claimedType ? { certificateType: claimedType } : {}),
      qscd: false,
      atIssuance: stripNote(atIssuance),
      atSigningTime: stripNote(atSigningTime),
      notes,
    });
  }
  const qualified = atIssuance.qualified && atSigningTime.qualified;
  const type =
    atIssuance.type && atSigningTime.type && atIssuance.type !== atSigningTime.type
      ? undefined
      : (atIssuance.type ?? atSigningTime.type);
  const qscd = qualified && atSigningTime.qscd;

  // The default type for a QC without QcType only applies to qualified
  // certificates; otherwise only the certificate's own QcType is reported.
  const reportedType = qualified ? type : claimedType;
  const fields = {
    qualifiedCertificate: qualified,
    ...(reportedType ? { certificateType: reportedType } : {}),
    qscd,
    atIssuance: stripNote(atIssuance),
    atSigningTime: stripNote(atSigningTime),
  };

  if (!qualified) {
    return buildResult(nonQualifiedLevel(reportedType), { ...fields, notes });
  }
  if (type === "esign") {
    return buildResult(qscd ? "QESig" : "AdESig-QC", { ...fields, notes });
  }
  if (type === "eseal") {
    return buildResult(qscd ? "QESeal" : "AdESeal-QC", { ...fields, notes });
  }
  if (type === "web") {
    return buildResult("AdES", {
      ...fields,
      notes: [
        ...notes,
        "The certificate is qualified for website authentication, not for signatures or seals",
      ],
    });
  }
  return buildResult("INDETERMINATE", {
    ...fields,
    notes: notes.length > 0 ? notes : ["The certificate type could not be determined"],
  });
}
