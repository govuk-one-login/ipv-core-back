import config from "../config/config.js";
import { EvcsStubPostVcsRequest } from "../types/evcs-stub.js";

export const postCredentials = async (
  userId: string,
  body: EvcsStubPostVcsRequest,
): Promise<void> => {
  const response = await fetch(`${config.evcs.baseUrl}/vcs/${userId}`, {
    headers: {
      "x-api-key": config.evcs.apiKey,
    },
    method: "POST",
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`generateVc request failed: ${response.statusText}`);
  }
};
