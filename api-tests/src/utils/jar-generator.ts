import * as jose from "jose";
import config from "../config/config.js";
import fs from "node:fs/promises";
import * as path from "path";
import { fileURLToPath } from "url";
import { getRandomString } from "./random-string-generator.js";
import { createEvcsAccessToken, createSignedJwt } from "./jwt-signer.js";
import { IpvSessionDetails } from "./ipv-session.js";
import { JarRequest } from "../types/jar-request.js";

const encAlg = "RSA-OAEP-256";
const encMethod = "A256GCM";
const encKey = await jose.importJWK(
  JSON.parse(config.core.encryptionKey) as jose.JWK,
  encAlg,
);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const generateJarPayload = async (
  session: IpvSessionDetails,
  redirectUrl: string | undefined,
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
      redirect_uri: redirectUrl || config.orch.redirectUrl,
    },
  };

  payload.claims.userinfo[
    "https://vocab.account.gov.uk/v1/storageAccessToken"
  ].values = [await createEvcsAccessToken(session.subject)];

  if (session.inheritedIdentityId) {
    const inheritedIdentity = JSON.parse(
      await fs.readFile(
        path.join(
          __dirname,
          `../../data/inherited-identities/${session.inheritedIdentityId}.json`,
        ),
        "utf8",
      ),
    );
    payload.claims.userinfo[
      "https://vocab.account.gov.uk/v1/inheritedIdentityJWT"
    ] = { values: [await createSignedJwt(inheritedIdentity)] };
  }

  return payload;
};

export const encryptJarRequest = async (payload: JarRequest): Promise<string> =>
  await new jose.CompactEncrypt(
    new TextEncoder().encode(await createSignedJwt(payload)),
  )
    .setProtectedHeader({ alg: encAlg, enc: encMethod })
    .encrypt(encKey);
