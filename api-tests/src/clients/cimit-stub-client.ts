import config from "../config/config.js";
import { CimitStubDetectRequest } from "../types/cimit-stub.js";

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
