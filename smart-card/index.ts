import { readFile } from "fs/promises";
import * as jose from "node-jose";
import { deflateRawSync } from "zlib";

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

getKeyStore().then(async (keys) => {
  console.log(
    `shc:/${toDecimalString(
      (
        await sign(
          await jose.JWK.asKey(keys.all()[0]),
          compressData(Buffer.from(`{"hello": "world"}`, "utf8")),
          { format: "compact", fields: { zip: "DEF" } }
        )
      ).toString()
    )}`
  );
});
