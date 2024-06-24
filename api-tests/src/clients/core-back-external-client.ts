import config from "../config/config.js";
import { TokenResponse } from "../interfaces/token-response.js";
import { UserIdentity } from "../interfaces/user-identity.js";

export const exchangeCodeForToken = async (
  tokenExchangeBody: string,
): Promise<TokenResponse> => {
  const response = await fetch(config.CORE_BACK_EXTERNAL_API_URL + "/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: tokenExchangeBody,
  });

  if (!response.ok) {
    throw new Error(
      "exchangeCodeForToken request failed: " + response.statusText,
    );
  }

  return await response.json();
};

export const getIdentity = async (
  tokenResponse: TokenResponse,
): Promise<UserIdentity> => {
  const response = await fetch(
    config.CORE_BACK_EXTERNAL_API_URL + `/user-identity`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${tokenResponse.access_token}`,
      },
    },
  );

  if (!response.ok) {
    throw new Error("getIdentity request failed: " + response.statusText);
  }

  return (await response.json()) as UserIdentity;
};
