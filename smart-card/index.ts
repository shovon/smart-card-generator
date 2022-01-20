import { readFile } from "fs/promises";
import * as jose from "node-jose";
import { deflateRawSync } from "zlib";
import * as qrcode from "qrcode";

let keyStore: jose.JWK.KeyStore | null = null;

async function getKeyStore(): Promise<jose.JWK.KeyStore> {
  if (!keyStore) {
    keyStore = await jose.JWK.asKeyStore(
      (await readFile("./privatekey.json")).toString()
    );
  }

  return keyStore;
}

function compressData(data: Buffer): Buffer {
  return deflateRawSync(data);
}

async function sign(
  key: jose.JWK.Key,
  data: Buffer,
  options: jose.JWS.SignOptions
): Promise<string> {
  const value = await jose.JWS.createSign(options, key).update(data).final();
  return value as unknown as string;
}

function toDecimalString(value: string): string {
  return value
    .split("")
    .map((c) => (c.charCodeAt(0) - 45).toString().padStart(2, "0"))
    .join("");
}

function smartCardFormat(str: string): string {
  return `shc:/${toDecimalString(str)}`;
}

function generateSmartCardPayload(): any {
  return {
    // iss: "https://smarthealthcard.phsa.ca/v1/issuer",
    iss: "https://raw.githubusercontent.com/shovon/smart-card-generator/main/public-key-store/v1/issuer",
    nbf: 1635675317,
    vc: {
      type: [
        "https://smarthealth.cards#covid19",
        "https://smarthealth.cards#immunization",
        "https://smarthealth.cards#health-card",
      ],
      credentialSubject: {
        fhirVersion: "4.0.1",
        fhirBundle: {
          resourceType: "Bundle",
          type: "collection",
          entry: [
            {
              fullUrl: "resource:0",
              resource: {
                resourceType: "Patient",
                name: [
                  {
                    family: "MCSMARTYPANTS",
                    given: ["SMARTY", "SMART"],
                  },
                ],
                birthDate: "1976-01-10",
              },
            },
            {
              fullUrl: "resource:1",
              resource: {
                resourceType: "Immunization",
                meta: {
                  security: [
                    {
                      system: "https://smarthealth.cards/ial",
                      code: "IAL1.4",
                    },
                  ],
                },
                status: "completed",
                vaccineCode: {
                  coding: [
                    {
                      system: "http://hl7.org/fhir/sid/cvx",
                      code: "210",
                    },
                    {
                      system: "http://snomed.info/sct",
                      code: "28761000087108",
                    },
                  ],
                },
                patient: {
                  reference: "resource:0",
                },
                occurrenceDateTime: "2021-05-01",
                manufacturer: {
                  identifier: {
                    system: "http://hl7.org/fhir/sid/mvx",
                    value: "MOD",
                  },
                },
                lotNumber: "CTMAV532",
                performer: [
                  {
                    actor: {
                      display: "North Pole",
                    },
                  },
                ],
              },
            },
            {
              fullUrl: "resource:2",
              resource: {
                resourceType: "Immunization",
                meta: {
                  security: [
                    {
                      system: "https://smarthealth.cards/ial",
                      code: "IAL1.4",
                    },
                  ],
                },
                status: "completed",
                vaccineCode: {
                  coding: [
                    {
                      system: "http://hl7.org/fhir/sid/cvx",
                      code: "207",
                    },
                    {
                      system: "http://snomed.info/sct",
                      code: "28571000087109",
                    },
                  ],
                },
                patient: {
                  reference: "resource:0",
                },
                occurrenceDateTime: "2021-05-21",
                manufacturer: {
                  identifier: {
                    system: "http://hl7.org/fhir/sid/mvx",
                    value: "MOD",
                  },
                },
                lotNumber: "043D21A",
                performer: [
                  {
                    actor: {
                      display: "North Pole",
                    },
                  },
                ],
              },
            },
          ],
        },
      },
    },
  };
}

getKeyStore().then(async (keys) => {
  const data = smartCardFormat(
    (
      await sign(
        await jose.JWK.asKey(keys.all()[0]),
        compressData(
          Buffer.from(JSON.stringify(generateSmartCardPayload()), "utf8")
        ),
        { format: "compact", fields: { zip: "DEF" } }
      )
    ).toString()
  );

  qrcode.toDataURL(data, { type: "terminal" }, (err, url) => {
    console.log(url);
  });
});
