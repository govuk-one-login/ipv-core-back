import config from "../config/config.js";
import {
  MfaResetResult,
  TokenResponse,
  UserIdentity,
} from "../types/external-api.js";

export const exchangeCodeForToken = async (
  tokenExchangeBody: string,
): Promise<TokenResponse> => {
  const response = await fetch(`${config.core.externalApiUrl}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: tokenExchangeBody,
  });

  if (!response.ok) {
    throw new Error(
      `exchangeCodeForToken request failed: ${response.statusText}`,
    );
  }

  return await response.json();
};

export const getIdentity = async (
  tokenResponse: TokenResponse,
): Promise<UserIdentity> => {
  const response = await fetch(`${config.core.externalApiUrl}/user-identity`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${tokenResponse.access_token}`,
      "content-type": "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`getIdentity request failed: ${response.statusText}`);
  }

  return (await response.json()) as UserIdentity;
};

export const getMfaResetResult = async (
  tokenResponse: TokenResponse,
): Promise<MfaResetResult> => {
  const response = await fetch(`${config.core.externalApiUrl}/reverification`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${tokenResponse.access_token}`,
      "content-type": "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`getMfaResetResult request failed: ${response.statusText}`);
  }

  return (await response.json()) as MfaResetResult;
};

export const healthcheck = async (): Promise<boolean> => {
  const response = await fetch(`${config.core.externalApiUrl}/healthcheck`, {
    method: "GET",
  });

  return response.ok;
};
