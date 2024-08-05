import * as jose from "jose";
import config from "../config/config.js";
import fs from "node:fs/promises";
import * as path from "path";
import { fileURLToPath } from "url";
import { getRandomString } from "./random-string-generator.js";
import { createEvcsAccessToken, createSignedJwt } from "./jwt-signer.js";

const encAlg = "RSA-OAEP-256";
const encMethod = "A256GCM";
const encKey = await jose.importJWK(
  JSON.parse(config.core.encryptionkey) as jose.JWK,
  encAlg,
);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const generateJar = async (
  subject: string,
  journeyId: string,
  journeyType: string,
): Promise<string> => {
  const payloadData = JSON.parse(
    await fs.readFile(
      path.join(__dirname, `../../data/jar-requests/${journeyType}.json`),
      "utf8",
    ),
  );
  const payload = {
    ...payloadData,
    ...{
      sub: subject,
      govuk_signin_journey_id: journeyId,
      state: getRandomString(16),
      redirect_uri: config.orch.redirectUrl,
    },
  };

  payload.claims.userinfo[
    "https://vocab.account.gov.uk/v1/storageAccessToken"
  ].values = [await createEvcsAccessToken(subject)];

  return await new jose.CompactEncrypt(
    new TextEncoder().encode(await createSignedJwt(payload)),
  )
    .setProtectedHeader({ alg: encAlg, enc: encMethod })
    .encrypt(encKey);
};
