import config from "../config/config.js";
import {
  EvcsStoredIdentity,
  EvcsStubPostVcsRequest,
} from "../types/evcs-stub.js";

export const postCredentials = async (
  userId: string,
  body: EvcsStubPostVcsRequest,
): Promise<void> => {
  const response = await fetch(`${config.evcs.baseUrl}/vcs/${userId}`, {
    headers: {
      "x-api-key": config.evcs.apiKey,
      "content-type": "application/json",
    },
    method: "POST",
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`generateVc request failed: ${response.statusText}`);
  }
};

export const getStoredIdentity = async (
  userId: string,
): Promise<{ statusCode: number; storedIdentities?: EvcsStoredIdentity[] }> => {
  const response = await fetch(
    `${config.evcs.baseUrl}/management/stored-identity/${userId}`,
    {
      headers: {
        "x-api-key": config.evcs.apiKey,
      },
      method: "GET",
    },
  );

  if (response.status === 404) {
    return { statusCode: 404 };
  }

  if (!response.ok) {
    throw new Error(
      `Failed to get stored identity from EVCS: ${response.statusText}`,
    );
  }

  return {
    statusCode: response.status,
    storedIdentities: await response.json(),
  };
};
