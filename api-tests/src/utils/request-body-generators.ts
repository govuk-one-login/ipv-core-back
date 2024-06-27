import config from "../config/config.js";
import { generateJar } from "./jar-generator.js";
import path from "path";
import { fileURLToPath } from "url";
import fs from "node:fs/promises";
import { createSignedJwt } from "./jwt-signer.js";
import { CriStubRequest, CriStubResponse } from "../types/cri-stub.js";
import {
  AuthRequestBody,
  ProcessCriCallbackRequest,
} from "../types/internal-api.js";

const ORCHESTRATOR_CLIENT_ID = "orchestrator";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
type JsonType = "credentialSubject" | "evidence";

export const generateInitialiseIpvSessionBody = async (
  subject: string,
  journeyType: string,
): Promise<AuthRequestBody> => {
  return {
    responseType: "code",
    clientId: "orchestrator",
    redirectUri: config.ORCHESTRATOR_REDIRECT_URL,
    state: "api-tests-state",
    scope: "openid",
    request: await generateJar(subject, journeyType),
  };
};

export const generateProcessCriCallbackBody = (
  criStubResponse: CriStubResponse,
): ProcessCriCallbackRequest => {
  const url = new URL(criStubResponse.redirectUri);
  const params = url.searchParams;
  const code = params.get("code");
  const state = params.get("state");
  const criId = params.get("id") || url.pathname.split("/")[3];
  if (!code || !state || !criId) {
    throw new Error(`Param missing from CRI callback redirect`, {
      cause: { code: code, state: state, criId: criId },
    });
  }
  return {
    authorizationCode: code,
    state: state,
    redirectUri: `${url.protocol}//${url.host}${url.pathname}`,
    credentialIssuerId: criId,
  };
};

export const generateCriStubBody = async (
  criId: string,
  scenario: string,
  redirectUrl: string,
): Promise<CriStubRequest> => {
  const urlParams = new URL(redirectUrl).searchParams;
  return {
    clientId: urlParams.get("client_id") as string,
    request: urlParams.get("request") as string,
    credentialSubjectJson: await readJsonFile(
      criId,
      scenario,
      "credentialSubject",
    ),
    evidenceJson: await readJsonFile(criId, scenario, "evidence"),
  };
};

export const generateTokenExchangeBody = async (
  redirectUrl: string,
): Promise<string> => {
  const code = new URL(redirectUrl).searchParams.get("code");
  if (!code) {
    throw new Error("code not received in redirect URL");
  }

  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("code", code);
  params.set("redirect_uri", config.ORCHESTRATOR_REDIRECT_URL);
  params.set("client_id", ORCHESTRATOR_CLIENT_ID);
  params.set(
    "client_assertion_type",
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  );
  params.set(
    "client_assertion",
    await createSignedJwt({
      sub: ORCHESTRATOR_CLIENT_ID,
      iss: ORCHESTRATOR_CLIENT_ID,
    }),
  );

  return params.toString();
};

const readJsonFile = async (
  criId: string,
  scenario: string,
  jsonType: JsonType,
) => {
  return await fs.readFile(
    path.join(
      __dirname,
      `../../data/cri-stub-requests/${criId}/${scenario}/${jsonType}.json`,
    ),
    "utf8",
  );
};
