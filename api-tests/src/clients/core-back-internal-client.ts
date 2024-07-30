import config from "../config/config.js";
import {
  AuthRequestBody,
  JourneyEngineResponse,
  JourneyResponse,
  PageResponse,
  ProcessCriCallbackRequest,
} from "../types/internal-api.js";

const JOURNEY_PREFIX = "/journey/";
const POST = "POST";

export const initialiseIpvSession = async (
  requestBody: AuthRequestBody,
): Promise<string> => {
  const response = await fetch(
    `${config.core.internalApiUrl}/session/initialise`,
    {
      method: "POST",
      headers: internalApiHeaders,
      body: JSON.stringify(requestBody),
    },
  );

  if (!response.ok) {
    throw new Error(
      `InitialiseIpvSession request failed: ${response.statusText}`,
    );
  }
  const responseBody = await response.json();

  return responseBody.ipvSessionId as string;
};

export const sendJourneyEvent = async (
  event: string,
  ipvSessionId: string,
): Promise<JourneyEngineResponse> => {
  const url = `${config.core.internalApiUrl}${event.startsWith(JOURNEY_PREFIX) ? event : JOURNEY_PREFIX + event}`;
  const response = await fetch(url, {
    method: POST,
    headers: { ...internalApiHeaders, ...{ "ipv-session-id": ipvSessionId } },
  });

  if (!response.ok) {
    throw new Error(`sendJourneyEvent request failed: ${response.statusText}`);
  }

  return (await response.json()) as JourneyEngineResponse;
};

export const processCriCallback = async (
  requestBody: ProcessCriCallbackRequest,
  ipvSessionId: string,
): Promise<JourneyResponse | PageResponse> => {
  const response = await fetch(`${config.core.internalApiUrl}/cri/callback`, {
    method: POST,
    headers: { ...internalApiHeaders, ...{ "ipv-session-id": ipvSessionId } },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(`sendJourneyEvent request failed: ${response.statusText}`);
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
