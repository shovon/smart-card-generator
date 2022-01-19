import * as jose from "node-jose";

const keyStore = jose.JWK.createKeyStore();

keyStore.generate("EC", "P-256", { alg: "ES256", use: "sig" }).then(() => {
  console.log(JSON.stringify(keyStore.toJSON(true)));
});
