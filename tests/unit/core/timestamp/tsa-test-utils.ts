// Helpers for building RFC 3161 timestamp tokens in tests.

import * as asn1js from "asn1js";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
  Attribute,
  CertificateChoices,
  CertificateSet,
  ContentInfo,
  DigestAlgorithmIdentifiers,
  EncapsulatedContent,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignedData,
  SignerIdentifier,
  SignerInfo,
  SignerInfos,
} from "@peculiar/asn1-cms";
import { MessageImprint, TSTInfo } from "@peculiar/asn1-tsp";
import { AlgorithmIdentifier, Certificate, SubjectKeyIdentifier } from "@peculiar/asn1-x509";
import { RsaSaPssParams, id_mgf1, id_sha256 } from "@peculiar/asn1-rsa";

const subtle = globalThis.crypto.subtle;
x509.cryptoProvider.set(globalThis.crypto);

export const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_ATTR_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
const OID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
const OID_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

export type KeyKind = "RSA" | "RSA-PSS" | "ECDSA-P256" | "ECDSA-P384";

export interface TestTsa {
  kind: KeyKind;
  cert: x509.X509Certificate;
  /** Private key usable for the token signature algorithm */
  signingKey: CryptoKey;
}

let serialCounter = 1;

export async function createTestTsa(
  kind: KeyKind,
  options: { name?: string; timeStampingEku?: boolean } = {},
): Promise<TestTsa> {
  const name = options.name ?? `CN=Test TSA ${kind} ${serialCounter}, O=edockit tests, C=LV`;
  let keyAlg: RsaHashedKeyGenParams | EcKeyGenParams;
  if (kind === "RSA" || kind === "RSA-PSS") {
    keyAlg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
  } else {
    keyAlg = { name: "ECDSA", namedCurve: kind === "ECDSA-P256" ? "P-256" : "P-384" };
  }
  const keys = (await subtle.generateKey(keyAlg, true, ["sign", "verify"])) as CryptoKeyPair;

  const eku = options.timeStampingEku === false ? [OID_KP_CLIENT_AUTH] : [OID_KP_TIME_STAMPING];
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: (serialCounter++).toString(16).padStart(4, "0") + "a1b2c3",
    name,
    notBefore: new Date("2020-01-01T00:00:00Z"),
    notAfter: new Date("2040-01-01T00:00:00Z"),
    signingAlgorithm: kind.startsWith("ECDSA") ? { name: "ECDSA", hash: "SHA-256" } : keyAlg,
    keys,
    extensions: [
      new x509.ExtendedKeyUsageExtension(eku, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });

  let signingKey = keys.privateKey;
  if (kind === "RSA-PSS") {
    const pkcs8 = await subtle.exportKey("pkcs8", keys.privateKey);
    signingKey = await subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["sign"],
    );
  }

  return { kind, cert, signingKey };
}

export async function sha256(data: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
  return subtle.digest("SHA-256", data as BufferSource);
}

function rawEcdsaToDer(raw: ArrayBuffer): ArrayBuffer {
  const bytes = new Uint8Array(raw);
  const half = bytes.length / 2;
  const toInteger = (part: Uint8Array) => {
    let start = 0;
    while (start < part.length - 1 && part[start] === 0) start++;
    let value = part.slice(start);
    if (value[0] & 0x80) {
      const padded = new Uint8Array(value.length + 1);
      padded.set(value, 1);
      value = padded;
    }
    return new asn1js.Integer({ valueHex: value });
  };
  return new asn1js.Sequence({
    value: [toInteger(bytes.subarray(0, half)), toInteger(bytes.subarray(half))],
  }).toBER(false);
}

function signatureAlgorithmFor(kind: KeyKind): AlgorithmIdentifier {
  switch (kind) {
    case "RSA":
      return new AlgorithmIdentifier({ algorithm: "1.2.840.113549.1.1.11", parameters: null });
    case "RSA-PSS": {
      const params = new RsaSaPssParams({
        hashAlgorithm: new AlgorithmIdentifier({ algorithm: id_sha256, parameters: null }),
        maskGenAlgorithm: new AlgorithmIdentifier({
          algorithm: id_mgf1,
          parameters: AsnConvert.serialize(
            new AlgorithmIdentifier({ algorithm: id_sha256, parameters: null }),
          ),
        }),
        saltLength: 32,
      });
      return new AlgorithmIdentifier({
        algorithm: "1.2.840.113549.1.1.10",
        parameters: AsnConvert.serialize(params),
      });
    }
    case "ECDSA-P256":
    case "ECDSA-P384":
      return new AlgorithmIdentifier({ algorithm: "1.2.840.10045.4.3.2" });
  }
}

async function sign(tsa: TestTsa, data: ArrayBuffer): Promise<ArrayBuffer> {
  switch (tsa.kind) {
    case "RSA":
      return subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, tsa.signingKey, data);
    case "RSA-PSS":
      return subtle.sign({ name: "RSA-PSS", saltLength: 32 }, tsa.signingKey, data);
    default:
      return rawEcdsaToDer(
        await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, tsa.signingKey, data),
      );
  }
}

export interface BuildTokenOptions {
  /** The data whose SHA-256 hash goes into the message imprint */
  imprintData: Uint8Array;
  genTime?: Date;
  /** Certificates embedded in the token (default: [tsa.cert]) */
  certificates?: x509.X509Certificate[];
  /** Certificate referenced by SignerInfo.sid (default: tsa.cert) */
  sidCertificate?: x509.X509Certificate;
  /** Use subjectKeyIdentifier instead of issuerAndSerialNumber for sid */
  useSubjectKeyIdentifier?: boolean;
  /** Certificate hashed into SigningCertificateV2 (default: tsa.cert, null to omit) */
  essCertificate?: x509.X509Certificate | null;
  /** Replace the embedded TSTInfo after the signature has been computed */
  replaceTstInfo?: (original: TSTInfo) => TSTInfo;
  /** Modify the signature bytes */
  tamperSignature?: boolean;
}

/**
 * Build a base64 RFC 3161 TimeStampToken signed by the given test TSA
 */
export async function buildTimestampToken(
  tsa: TestTsa,
  options: BuildTokenOptions,
): Promise<string> {
  const sidCert = options.sidCertificate ?? tsa.cert;
  const embedded = options.certificates ?? [tsa.cert];
  const essCert = options.essCertificate === undefined ? tsa.cert : options.essCertificate;

  const tstInfo = new TSTInfo({
    version: 1,
    policy: "1.2.3.4.5",
    messageImprint: new MessageImprint({
      hashAlgorithm: new AlgorithmIdentifier({ algorithm: OID_SHA256, parameters: null }),
      hashedMessage: new OctetString(await sha256(options.imprintData)),
    }),
    serialNumber: new Uint8Array([0x01, 0x23, 0x45, 0x67]).buffer,
    genTime: options.genTime ?? new Date("2025-06-01T12:00:00Z"),
  });
  const tstDer = AsnConvert.serialize(tstInfo);

  const attributes: Attribute[] = [
    new Attribute({
      attrType: OID_ATTR_CONTENT_TYPE,
      attrValues: [new asn1js.ObjectIdentifier({ value: OID_CT_TST_INFO }).toBER(false)],
    }),
    new Attribute({
      attrType: OID_ATTR_MESSAGE_DIGEST,
      attrValues: [new asn1js.OctetString({ valueHex: await sha256(tstDer) }).toBER(false)],
    }),
  ];
  if (essCert) {
    // SigningCertificateV2 { certs SEQUENCE OF ESSCertIDv2 { certHash (SHA-256 default) } }
    const certHash = await sha256(essCert.rawData);
    attributes.push(
      new Attribute({
        attrType: OID_ATTR_SIGNING_CERTIFICATE_V2,
        attrValues: [
          new asn1js.Sequence({
            value: [
              new asn1js.Sequence({
                value: [
                  new asn1js.Sequence({ value: [new asn1js.OctetString({ valueHex: certHash })] }),
                ],
              }),
            ],
          }).toBER(false),
        ],
      }),
    );
  }

  // DER(SET OF Attribute) is what gets signed
  const signedAttrsDer = new asn1js.Set({
    value: attributes.map((a) => asn1js.fromBER(AsnConvert.serialize(a)).result),
  }).toBER(false);

  let signature = new Uint8Array(await sign(tsa, signedAttrsDer));
  if (options.tamperSignature) {
    signature = signature.slice();
    signature[signature.length - 5] ^= 0x01;
  }

  const sidAsn = AsnConvert.parse(sidCert.rawData, Certificate);
  let sid: SignerIdentifier;
  if (options.useSubjectKeyIdentifier) {
    const skiExt = sidCert.getExtension(x509.SubjectKeyIdentifierExtension);
    if (!skiExt) throw new Error("certificate has no SKI");
    sid = new SignerIdentifier({
      subjectKeyIdentifier: new SubjectKeyIdentifier(
        new Uint8Array(Buffer.from(skiExt.keyId, "hex")),
      ),
    });
  } else {
    sid = new SignerIdentifier({
      issuerAndSerialNumber: new IssuerAndSerialNumber({
        issuer: sidAsn.tbsCertificate.issuer,
        serialNumber: sidAsn.tbsCertificate.serialNumber,
      }),
    });
  }

  const signerInfo = new SignerInfo({
    version: options.useSubjectKeyIdentifier ? 3 : 1,
    sid,
    digestAlgorithm: new AlgorithmIdentifier({ algorithm: OID_SHA256, parameters: null }),
    signedAttrs: attributes,
    signatureAlgorithm: signatureAlgorithmFor(tsa.kind),
    signature: new OctetString(signature),
  });

  const embeddedTstDer = options.replaceTstInfo
    ? AsnConvert.serialize(options.replaceTstInfo(AsnConvert.parse(tstDer, TSTInfo)))
    : tstDer;

  const signedData = new SignedData({
    version: 3,
    digestAlgorithms: new DigestAlgorithmIdentifiers([
      new AlgorithmIdentifier({ algorithm: OID_SHA256, parameters: null }),
    ]),
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: OID_CT_TST_INFO,
      eContent: new EncapsulatedContent({ single: new OctetString(embeddedTstDer) }),
    }),
    certificates: embedded.length
      ? new CertificateSet(
          embedded.map(
            (c) =>
              new CertificateChoices({ certificate: AsnConvert.parse(c.rawData, Certificate) }),
          ),
        )
      : undefined,
    signerInfos: new SignerInfos([signerInfo]),
  });

  const contentInfo = new ContentInfo({
    contentType: OID_SIGNED_DATA,
    content: AsnConvert.serialize(signedData),
  });
  return Buffer.from(AsnConvert.serialize(contentInfo)).toString("base64");
}
