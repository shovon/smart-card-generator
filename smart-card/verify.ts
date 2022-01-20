import * as jose from "node-jose";
import { readFile } from "fs/promises";
import { randomBytes } from "crypto";
import { createDeflateRaw, deflateRawSync } from "zlib";

let keyStore: jose.JWK.KeyStore | null = null;

async function getKeyStore(): Promise<jose.JWK.KeyStore> {
  if (!keyStore) {
    keyStore = await jose.JWK.asKeyStore(
      (await readFile("./publickey.json")).toString()
    );
  }

  return keyStore;
}

async function isValid(str: string): Promise<boolean> {
  try {
    const keyStore = await getKeyStore();
    const jwt = fromSmartCardFormat(str);
    const result = await jose.JWS.createVerify(keyStore).verify(jwt);
    console.log(result);
    return true;
  } catch (e) {
    return false;
  }
}

function fromDecimalString(value: string): string {
  return value
    .match(/../g)
    .map((c) => String.fromCharCode(parseInt(c, 10) + 45))
    .join("");
}

function fromSmartCardFormat(str: string) {
  return fromDecimalString(str.slice(5));
}

isValid(
  "shc:/5676290952432060346029243740446031222959532654603460292540772804336028702864716745222809286436033340596940654177322404093423293352034567452633323862753040394559364167454564254437775575330545765665553853641160573601680453303832062976415676406320687776503038412668213620013954683432590762041126575753073211696136394411573258207235522466122411436741434324230065425966412534575012433361363110390037776360452162720944656131501126612376717508257074"
).then((result) => {
  console.log(result);
});
