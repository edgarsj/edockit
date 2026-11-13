import * as asn1js from "asn1js";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Name } from "@peculiar/asn1-x509";
import {
  CertificatePolicyExtension,
  ExtendedKeyUsageExtension,
  KeyUsagesExtension,
  X509Certificate,
} from "@peculiar/x509";

/** qcStatements certificate extension (RFC 3739) */
export const QC_STATEMENTS_OID = "1.3.6.1.5.5.7.1.3";

/** ETSI EN 319 412-5 statement and type identifiers */
export const QC_STATEMENT_OIDS = {
  qcCompliance: "0.4.0.1862.1.1",
  qcLimitValue: "0.4.0.1862.1.2",
  qcRetentionPeriod: "0.4.0.1862.1.3",
  qcSSCD: "0.4.0.1862.1.4",
  qcPDS: "0.4.0.1862.1.5",
  qcType: "0.4.0.1862.1.6",
  qcCClegislation: "0.4.0.1862.1.7",
  pkixQCSyntaxV1: "1.3.6.1.5.5.7.11.1",
  pkixQCSyntaxV2: "1.3.6.1.5.5.7.11.2",
} as const;

const QC_TYPE_OIDS: Record<string, QcType> = {
  "0.4.0.1862.1.6.1": "esign",
  "0.4.0.1862.1.6.2": "eseal",
  "0.4.0.1862.1.6.3": "web",
};

/**
 * Pre-eIDAS qualified certificate policies (ETSI TS 101 456): QCP public and
 * QCP public + SSCD.
 */
export const PRE_EIDAS_QC_POLICY_OIDS = ["0.4.0.1456.1.2", "0.4.0.1456.1.1"] as const;
export const PRE_EIDAS_QC_SSCD_POLICY_OID = "0.4.0.1456.1.1";

/** Purpose of a qualified certificate (QcType) */
export type QcType = "esign" | "eseal" | "web";

export interface QcPdsLocation {
  url: string;
  language: string;
}

/** Statements of the certificate's qcStatements extension */
export interface QcStatements {
  /** QcCompliance: the certificate claims to be an EU qualified certificate */
  qcCompliance: boolean;
  /** QcSSCD: the certificate claims its private key is in a QSCD */
  qcQSCD: boolean;
  /** QcType values; unknown type OIDs are not listed */
  qcTypes: QcType[];
  /** QcCClegislation country codes (qualified under a non-EU legislation) */
  qcCClegislation?: string[];
  /** QcPDS PKI disclosure statement locations */
  qcPDS?: QcPdsLocation[];
  /** QcRetentionPeriod in years */
  qcRetentionPeriod?: number;
  /** Semantics identifier of the pkixQCSyntax-v2 statement, e.g. 0.4.0.194121.1.1 */
  semanticsIdentifier?: string;
  /** All statement identifiers present */
  statementIds: string[];
}

function sequenceItems(block: unknown): asn1js.AsnType[] {
  if (block instanceof asn1js.Sequence) {
    return block.valueBlock.value as asn1js.AsnType[];
  }
  return [];
}

function oidValue(block: unknown): string | undefined {
  return block instanceof asn1js.ObjectIdentifier ? block.valueBlock.toString() : undefined;
}

function stringValue(block: unknown): string | undefined {
  if (
    block instanceof asn1js.PrintableString ||
    block instanceof asn1js.IA5String ||
    block instanceof asn1js.Utf8String ||
    block instanceof asn1js.VisibleString
  ) {
    return block.valueBlock.value;
  }
  return undefined;
}

/**
 * Parse a DER-encoded QCStatements value (SEQUENCE OF QCStatement).
 * Statements that cannot be decoded are listed in `statementIds` only.
 */
export function parseQcStatementsValue(der: ArrayBuffer | ArrayBufferView): QcStatements {
  const buffer =
    der instanceof ArrayBuffer
      ? der
      : der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength);
  const parsed = asn1js.fromBER(buffer as ArrayBuffer);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) {
    throw new Error("Invalid qcStatements extension");
  }

  const result: QcStatements = {
    qcCompliance: false,
    qcQSCD: false,
    qcTypes: [],
    statementIds: [],
  };

  for (const statement of sequenceItems(parsed.result)) {
    const [idBlock, info] = sequenceItems(statement);
    const statementId = oidValue(idBlock);
    if (!statementId) {
      continue;
    }
    result.statementIds.push(statementId);

    switch (statementId) {
      case QC_STATEMENT_OIDS.qcCompliance:
        result.qcCompliance = true;
        break;
      case QC_STATEMENT_OIDS.qcSSCD:
        result.qcQSCD = true;
        break;
      case QC_STATEMENT_OIDS.qcType:
        for (const typeBlock of sequenceItems(info)) {
          const type = QC_TYPE_OIDS[oidValue(typeBlock) ?? ""];
          if (type && !result.qcTypes.includes(type)) {
            result.qcTypes.push(type);
          }
        }
        break;
      case QC_STATEMENT_OIDS.qcCClegislation: {
        const countries = sequenceItems(info)
          .map(stringValue)
          .filter((value): value is string => Boolean(value));
        if (countries.length > 0) {
          result.qcCClegislation = countries;
        }
        break;
      }
      case QC_STATEMENT_OIDS.qcPDS: {
        const locations = sequenceItems(info)
          .map((location) => {
            const [url, language] = sequenceItems(location).map(stringValue);
            return url ? { url, language: language ?? "" } : null;
          })
          .filter((value): value is QcPdsLocation => value !== null);
        if (locations.length > 0) {
          result.qcPDS = locations;
        }
        break;
      }
      case QC_STATEMENT_OIDS.qcRetentionPeriod:
        if (info instanceof asn1js.Integer) {
          result.qcRetentionPeriod = info.valueBlock.valueDec;
        }
        break;
      case QC_STATEMENT_OIDS.pkixQCSyntaxV1:
      case QC_STATEMENT_OIDS.pkixQCSyntaxV2: {
        const semanticsIdentifier = oidValue(sequenceItems(info)[0]);
        if (semanticsIdentifier) {
          result.semanticsIdentifier = semanticsIdentifier;
        }
        break;
      }
    }
  }

  return result;
}

/** Parse the qcStatements extension of a certificate; null when absent or malformed */
export function getQcStatements(certificate: X509Certificate): QcStatements | null {
  const extension = certificate.getExtension(QC_STATEMENTS_OID);
  if (!extension) {
    return null;
  }
  try {
    return parseQcStatementsValue(extension.value);
  } catch {
    return null;
  }
}

/** Key usage bit names as used in trusted lists, with their KeyUsageFlags values */
const KEY_USAGE_BITS: Array<[string, number]> = [
  ["digitalSignature", 1],
  ["nonRepudiation", 2],
  ["keyEncipherment", 4],
  ["dataEncipherment", 8],
  ["keyAgreement", 16],
  ["keyCertSign", 32],
  ["crlSign", 64],
  ["encipherOnly", 128],
  ["decipherOnly", 256],
];

/** Certificate properties used to evaluate trusted-list qualification criteria */
export interface CertificateQualificationFacts {
  notBefore: Date;
  qcStatements: QcStatements | null;
  /** Certificate policy OIDs */
  policies: string[];
  /** Key usage bits that are set (TS 119 612 names, e.g. "nonRepudiation", "crlSign") */
  keyUsage: Set<string> | null;
  /** Extended key usage OIDs */
  extendedKeyUsage: string[];
  /** Attribute type OIDs present in the subject DN */
  subjectAttributeOids: Set<string>;
}

export function getCertificateQualificationFacts(
  certificate: X509Certificate,
): CertificateQualificationFacts {
  const policyExtension = certificate.getExtension(CertificatePolicyExtension);
  const keyUsageExtension = certificate.getExtension(KeyUsagesExtension);
  const ekuExtension = certificate.getExtension(ExtendedKeyUsageExtension);

  let keyUsage: Set<string> | null = null;
  if (keyUsageExtension) {
    keyUsage = new Set(
      KEY_USAGE_BITS.filter(([, flag]) => (keyUsageExtension.usages & flag) !== 0).map(
        ([name]) => name,
      ),
    );
  }

  const subjectAttributeOids = new Set<string>();
  try {
    const name = AsnConvert.parse(certificate.subjectName.toArrayBuffer(), Name);
    for (const rdn of name) {
      for (const attribute of rdn) {
        subjectAttributeOids.add(attribute.type);
      }
    }
  } catch {
    // Leave empty; DN attribute criteria then do not match.
  }

  return {
    notBefore: certificate.notBefore,
    qcStatements: getQcStatements(certificate),
    policies: [...(policyExtension?.policies ?? [])],
    keyUsage,
    extendedKeyUsage: (ekuExtension?.usages ?? []).map(String),
    subjectAttributeOids,
  };
}
