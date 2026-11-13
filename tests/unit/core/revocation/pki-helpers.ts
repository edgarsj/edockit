// Helpers that build a small local PKI (CA, end-entity, OCSP responder) and
// OCSP responses / CRLs for revocation unit tests.

import {
  AlgorithmProvider,
  AsnEcSignatureFormatter,
  AuthorityInfoAccessExtension,
  BasicConstraintsExtension,
  CRLDistributionPointsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  Extension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  X509CertificateGenerator,
  X509CrlEntryParams,
  X509CrlGenerator,
} from "@peculiar/x509";
import { AsnConvert, AsnParser, OctetString } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import {
  BasicOCSPResponse,
  CertID,
  CertStatus,
  KeyHash,
  OCSPResponse,
  OCSPResponseStatus,
  ResponderID,
  ResponseBytes,
  ResponseData,
  RevokedInfo,
  SingleResponse,
} from "@peculiar/asn1-ocsp";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";

export const OCSP_URL = "http://ocsp.example.test/";
export const CRL_URL = "http://crl.example.test/ca.crl";
export const CA_ISSUERS_URL = "http://ca.example.test/ca.crt";
export const CA_NAME = "CN=Test Revocation CA, O=Example, C=LV";

export type KeyKind = "rsa" | "ec" | "pss";

export interface KeyAndAlg {
  keys: CryptoKeyPair;
  signingAlgorithm: Algorithm & { hash: { name: string }; namedCurve?: string };
}

export async function generateKey(kind: KeyKind = "rsa"): Promise<KeyAndAlg> {
  if (kind === "pss") {
    const keys = (await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    return {
      keys,
      signingAlgorithm: { name: "RSA-PSS", hash: { name: "SHA-256" }, saltLength: 32 } as never,
    };
  }
  if (kind === "ec") {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    return {
      keys,
      signingAlgorithm: { name: "ECDSA", hash: { name: "SHA-256" }, namedCurve: "P-256" },
    };
  }
  const keys = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return { keys, signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } } };
}

const DAY = 24 * 60 * 60 * 1000;

export async function createCA(name = CA_NAME, key?: KeyAndAlg) {
  const k = key ?? (await generateKey("rsa"));
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "0a",
    name,
    notBefore: new Date(Date.now() - DAY),
    notAfter: new Date(Date.now() + 365 * DAY),
    keys: k.keys,
    signingAlgorithm: k.signingAlgorithm,
    extensions: [
      new BasicConstraintsExtension(true, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
    ],
  });
  return { cert, ...k };
}

export type TestCA = Awaited<ReturnType<typeof createCA>>;

export async function issueCertificate(
  ca: TestCA,
  options: {
    subject: string;
    serialNumber: string;
    key?: KeyAndAlg;
    extensions?: Extension[];
    notBefore?: Date;
    notAfter?: Date;
  },
) {
  const k = options.key ?? (await generateKey("rsa"));
  const cert = await X509CertificateGenerator.create({
    serialNumber: options.serialNumber,
    subject: options.subject,
    issuer: ca.cert.subject,
    notBefore: options.notBefore ?? new Date(Date.now() - DAY),
    notAfter: options.notAfter ?? new Date(Date.now() + 180 * DAY),
    publicKey: k.keys.publicKey,
    signingKey: ca.keys.privateKey,
    signingAlgorithm: ca.signingAlgorithm,
    extensions: options.extensions ?? [],
  });
  return { cert, ...k };
}

export async function issueLeaf(ca: TestCA, serialNumber = "1234abcd") {
  return issueCertificate(ca, {
    subject: "CN=Test Signer, C=LV",
    serialNumber,
    extensions: [
      new AuthorityInfoAccessExtension({ ocsp: [OCSP_URL], caIssuers: [CA_ISSUERS_URL] }),
      new CRLDistributionPointsExtension([CRL_URL]),
    ],
  });
}

export async function issueResponder(
  ca: TestCA,
  options: { eku?: boolean; key?: KeyAndAlg; notAfter?: Date } = {},
) {
  const extensions: Extension[] = [];
  if (options.eku !== false) {
    extensions.push(new ExtendedKeyUsageExtension([ExtendedKeyUsage.ocspSigning]));
  }
  return issueCertificate(ca, {
    subject: "CN=Test OCSP Responder, C=LV",
    serialNumber: "77",
    key: options.key,
    extensions,
    notAfter: options.notAfter,
  });
}

async function sha1(data: BufferSource): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-1", data);
}

function certAsn(cert: X509Certificate): Certificate {
  return AsnParser.parse(cert.rawData, Certificate);
}

function hexToBuffer(hex: string): ArrayBuffer {
  const clean = hex.length % 2 ? `0${hex}` : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out.buffer;
}

export async function buildCertId(cert: X509Certificate, issuer: X509Certificate) {
  const issuerAsn = certAsn(issuer);
  return new CertID({
    hashAlgorithm: new AlgorithmIdentifier({ algorithm: "1.3.14.3.2.26", parameters: null }),
    issuerNameHash: new OctetString(
      await sha1(AsnConvert.serialize(issuerAsn.tbsCertificate.subject)),
    ),
    issuerKeyHash: new OctetString(
      await sha1(issuerAsn.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey),
    ),
    serialNumber: hexToBuffer(cert.serialNumber),
  });
}

export interface OCSPResponseParams {
  /** Certificate the response is about */
  cert: X509Certificate;
  /** Issuer used to compute the CertID */
  issuer: X509Certificate;
  /** Certificate whose key signs the response (identified in responderID) */
  signerCert: X509Certificate;
  /** Key and algorithm used to sign */
  signer: KeyAndAlg;
  /** Certificates to embed in the response */
  certs?: X509Certificate[];
  status?: "good" | "revoked" | "unknown";
  revokedAt?: Date;
  thisUpdate?: Date;
  nextUpdate?: Date | null;
  responderIdByName?: boolean;
  /** Overrides the CertID (e.g. to point at another certificate) */
  certId?: CertID;
  corruptSignature?: boolean;
}

export async function buildOCSPResponse(params: OCSPResponseParams): Promise<ArrayBuffer> {
  const now = Date.now();
  const thisUpdate = params.thisUpdate ?? new Date(now - 60 * 1000);
  const nextUpdate =
    params.nextUpdate === null ? undefined : (params.nextUpdate ?? new Date(now + 60 * 60 * 1000));

  const status = params.status ?? "good";
  const certStatus =
    status === "good"
      ? new CertStatus({ good: null })
      : status === "revoked"
        ? new CertStatus({
            revoked: new RevokedInfo({
              revocationTime: params.revokedAt ?? new Date(now - DAY),
            }),
          })
        : new CertStatus({ unknown: null });

  const signerAsn = certAsn(params.signerCert);
  const responderID = params.responderIdByName
    ? new ResponderID({ byName: signerAsn.tbsCertificate.subject })
    : new ResponderID({
        byKey: new KeyHash(
          await sha1(signerAsn.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey),
        ),
      });

  const tbs = new ResponseData({
    responderID,
    producedAt: new Date(now),
    responses: [
      new SingleResponse({
        certID: params.certId ?? (await buildCertId(params.cert, params.issuer)),
        certStatus,
        thisUpdate,
        nextUpdate,
      }),
    ],
  });
  const tbsDer = AsnConvert.serialize(tbs);

  const alg = params.signer.signingAlgorithm;
  let signature = await crypto.subtle.sign(alg, params.signer.keys.privateKey, tbsDer);
  if (alg.name === "ECDSA") {
    signature = new AsnEcSignatureFormatter().toAsnSignature(alg, signature)!;
  }
  if (params.corruptSignature) {
    const bytes = new Uint8Array(signature.slice(0));
    bytes[bytes.length - 1] ^= 0x01;
    signature = bytes.buffer;
  }

  const basic = new BasicOCSPResponse({
    tbsResponseData: tbs,
    signatureAlgorithm: new AlgorithmProvider().toAsnAlgorithm(alg),
    signature,
    certs: (params.certs ?? []).map((c) => certAsn(c)),
  });

  const response = new OCSPResponse({
    responseStatus: OCSPResponseStatus.successful,
    responseBytes: new ResponseBytes({
      responseType: "1.3.6.1.5.5.7.48.1.1",
      response: new OctetString(AsnConvert.serialize(basic)),
    }),
  });
  return AsnConvert.serialize(response);
}

export async function buildCRL(
  ca: { cert: X509Certificate } & KeyAndAlg,
  options: {
    issuerName?: string;
    entries?: X509CrlEntryParams[];
    thisUpdate?: Date;
    nextUpdate?: Date;
  } = {},
): Promise<ArrayBuffer> {
  const crl = await X509CrlGenerator.create({
    issuer: options.issuerName ?? ca.cert.subject,
    thisUpdate: options.thisUpdate ?? new Date(Date.now() - 60 * 60 * 1000),
    nextUpdate: options.nextUpdate ?? new Date(Date.now() + DAY),
    entries: options.entries ?? [],
    signingKey: ca.keys.privateKey,
    signingAlgorithm: ca.signingAlgorithm,
  });
  return crl.rawData;
}
