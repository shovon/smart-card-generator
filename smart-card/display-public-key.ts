import * as jose from "node-jose";
import { readFile } from "fs/promises";

let keyStore: jose.JWK.KeyStore | null;

async function getKeyStore(): Promise<jose.JWK.KeyStore> {
  if (!keyStore) {
    keyStore = await jose.JWK.asKeyStore(
      (await readFile("./privatekey.json")).toString()
    );
  }

  return keyStore;
}

getKeyStore().then((store) => console.log(JSON.stringify(store.toJSON())));
