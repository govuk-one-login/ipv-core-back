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
  journeyId: string,
  journeyType: string,
  reproveIdentity: boolean,
): Promise<AuthRequestBody> => {
  return {
    responseType: "code",
    clientId: "orchestrator",
    redirectUri: config.orch.redirectUrl,
    state: "api-tests-state",
    scope: "openid",
    request: await generateJar(
      subject,
      journeyId,
      journeyType,
      reproveIdentity,
    ),
  };
};

export const generateProcessCriCallbackBody = (
  criStubResponse: CriStubResponse,
): ProcessCriCallbackRequest => {
  const url = new URL(criStubResponse.redirectUri);
  const params = url.searchParams;
  const criId = params.get("id") || url.pathname.split("/")[3];

  // Success params
  const code = params.get("code");
  const state = params.get("state");

  // Error params
  const error = params.get("error");
  const errorDescription = params.get("errorDescription");

  return {
    authorizationCode: code ?? undefined,
    state: state ?? undefined,
    error: error ?? undefined,
    errorDescription: errorDescription ?? undefined,
    redirectUri: `${url.protocol}//${url.host}${url.pathname}`,
    credentialIssuerId: criId,
  };
};

export const generateCriStubBody = async (
  criId: string,
  scenario: string,
  redirectUrl: string,
  nbf?: number,
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
    nbf,
  };
};

export const generateCriStubErrorBody = async (
  error: string,
  redirectUrl: string,
): Promise<CriStubRequest> => {
  const urlParams = new URL(redirectUrl).searchParams;
  return {
    clientId: urlParams.get("client_id") as string,
    request: urlParams.get("request") as string,
    requestedError: {
      error,
      description: "Error generated by API tests",
      endpoint: "auth",
      userInfoError: "none",
    },
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
  params.set("redirect_uri", config.orch.redirectUrl);
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
