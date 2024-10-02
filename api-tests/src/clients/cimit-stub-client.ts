import config from "../config/config.js";
import {
  CimitStubDetectRequest,
  CimitStubMitigateRequest,
} from "../types/cimit-stub.js";

export const postDetectCi = async (
  body: CimitStubDetectRequest,
): Promise<void> => {
  const response = await fetch(
    `${config.cimit.internalApiUrl}/contra-indicators/detect`,
    {
      headers: {
        "x-api-key": config.cimit.internalApiKey,
        "content-type": "application/json",
      },
      method: "POST",
      body: JSON.stringify(body),
    },
  );

  if (!response.ok) {
    throw new Error(`postDetectCI request failed: ${response.statusText}`);
  }
};

export const postMitigateCi = async (
  body: CimitStubMitigateRequest,
): Promise<void> => {
  const response = await fetch(
    `${config.cimit.internalApiUrl}/contra-indicators/mitigate`,
    {
      headers: {
        "x-api-key": config.cimit.internalApiKey,
        "content-type": "application/json",
      },
      method: "POST",
      body: JSON.stringify(body),
    },
  );

  if (!response.ok) {
    throw new Error(`postMitigateCI request failed: ${response.statusText}`);
  }
};
