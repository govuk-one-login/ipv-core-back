import * as jose from "jose";
import { BeforeAll } from "@cucumber/cucumber";
import config from "../config/config.js";
import fs from "node:fs/promises";
import * as path from "path";
import { fileURLToPath } from "url";
import { getRandomString } from "./random-string-generator.js";
import { createSignedJwt } from "./jwt-signer.js";
import { IpvSessionDetails } from "./ipv-session.js";
import { JarRequest } from "../types/jar-request.js";
import { jwks } from "../clients/core-back-external-client.js";
import { JWK } from "jose";
import { fetchEvcsAccessToken } from "../clients/evcs-stub-client.js";

const encAlg = "RSA-OAEP-256";
const encMethod = "A256GCM";

let encKeyJwk: JWK;
BeforeAll(async () => {
  try {
    const publicKeySet = await jwks();
    const encKey = publicKeySet.keys.find((key) => key.use === "enc");

    if (!encKey) {
      throw Error("No public encryption key found for core-back");
    }
    encKeyJwk = encKey;
  } catch (e) {
    console.log(`Exception caught getting public keys: ${e}`);
    throw e;
  }
});

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const generateJarPayload = async (
  session: IpvSessionDetails,
): Promise<JarRequest> => {
  const payloadData = JSON.parse(
    await fs.readFile(
      path.join(
        __dirname,
        `../../data/jar-requests/${session.journeyType}.json`,
      ),
      "utf8",
    ),
  ) as JarRequest;

  const payload = {
    ...payloadData,
    ...{
      reprove_identity: session.isReproveIdentity,
      sub: session.subject,
      govuk_signin_journey_id: session.journeyId,
      state: getRandomString(16),
      redirect_uri: payloadData.redirect_uri || config.orch.redirectUrl,
    },
  };

  payload.claims.userinfo[
    "https://vocab.account.gov.uk/v1/storageAccessToken"
  ].values = [await fetchEvcsAccessToken(session.subject)];

  return payload;
};

export const encryptJarRequest = async (
  payload: JarRequest,
): Promise<string> => {
  const encKey = await jose.importJWK(encKeyJwk, encAlg);

  return await new jose.CompactEncrypt(
    new TextEncoder().encode(await createSignedJwt(payload)),
  )
    .setProtectedHeader({
      alg: encAlg,
      enc: encMethod,
      kid: encKeyJwk.kid,
    })
    .encrypt(encKey);
};
