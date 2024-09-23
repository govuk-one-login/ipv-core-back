import config from "../config/config.js";
import {
  AuthRequestBody,
  JourneyEngineResponse,
  JourneyResponse,
  PageResponse,
  ProcessCriCallbackRequest,
} from "../types/internal-api.js";
import { ProvenUserIdentity } from "../types/internal-api.js";
import { ApiRequestError } from "../types/errors.js";

const JOURNEY_PREFIX = "/journey/";
const POST = "POST";
const GET = "GET";

export const initialiseIpvSession = async (
  requestBody: AuthRequestBody,
  featureSet: string | undefined,
): Promise<string> => {
  const response = await fetch(
    `${config.core.internalApiUrl}/session/initialise`,
    {
      method: "POST",
      headers: {
        ...internalApiHeaders,
        ...(featureSet ? { "feature-set": featureSet } : {}),
      },
      body: JSON.stringify(requestBody),
    },
  );

  const responseBody = await response.json();
  if (!response.ok) {
    throw new ApiRequestError(
      response.status,
      response.statusText,
      "InitialiseIpvSession",
      responseBody.message,
    );
  }

  return responseBody.ipvSessionId as string;
};

export const sendJourneyEvent = async (
  event: string,
  ipvSessionId: string,
  featureSet: string | undefined,
): Promise<JourneyEngineResponse> => {
  const url = `${config.core.internalApiUrl}${event.startsWith(JOURNEY_PREFIX) ? event : JOURNEY_PREFIX + event}`;
  const response = await fetch(url, {
    method: POST,
    headers: {
      ...internalApiHeaders,
      ...(featureSet ? { "feature-set": featureSet } : {}),
      "ipv-session-id": ipvSessionId,
      language: "en",
    },
  });

  if (!response.ok) {
    throw new Error(`sendJourneyEvent request failed: ${response.statusText}`);
  }

  return (await response.json()) as JourneyEngineResponse;
};

export const processCriCallback = async (
  requestBody: ProcessCriCallbackRequest,
  ipvSessionId: string,
  featureSet: string | undefined,
): Promise<JourneyResponse | PageResponse> => {
  const response = await fetch(`${config.core.internalApiUrl}/cri/callback`, {
    method: POST,
    headers: {
      ...internalApiHeaders,
      ...(featureSet ? { "feature-set": featureSet } : {}),
      ...{ "ipv-session-id": ipvSessionId },
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(
      `processCriCallback request failed: ${response.statusText}`,
    );
  }

  return await response.json();
};

export const getProvenIdentityDetails = async (
  ipvSessionId: string,
  featureSet: string | undefined,
): Promise<ProvenUserIdentity> => {
  const response = await fetch(
    `${config.core.internalApiUrl}/user/proven-identity-details`,
    {
      method: GET,
      headers: {
        ...internalApiHeaders,
        ...(featureSet ? { "feature-set": featureSet } : {}),
        ...{ "ipv-session-id": ipvSessionId },
      },
    },
  );

  if (!response.ok) {
    throw new Error(
      `BuildProvenUserIdentityDetails request failed: ${response.statusText}`,
    );
  }

  return await response.json();
};

const internalApiHeaders: Record<string, string> = {
  "Content-Type": "application/json",
  "ip-address": "unknown",
  ...(config.core.internalApiKey && {
    "x-api-key": config.core.internalApiKey,
  }),
};
