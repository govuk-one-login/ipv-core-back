import config from "../config/config.js";
import {
  CimitStubDetectRequest,
  CimitStubUserCisRequest,
} from "../types/cimit-stub.js";

export const postDetectCi = async (
  journeyId: string,
  body: CimitStubDetectRequest,
): Promise<void> => {
  const response = await fetch(
    `${config.cimit.internalApiUrl}/contra-indicators/detect`,
    {
      headers: {
        "x-api-key": config.cimit.internalApiKey,
        "content-type": "application/json",
        "govuk-signin-journey-id": journeyId,
        "ip-address": "192.168.1.1",
      },
      method: "POST",
      body: JSON.stringify(body),
    },
  );

  if (!response.ok) {
    throw new Error(`postDetectCI request failed: ${response.statusText}`);
  }
};

export const createUserCi = async (
  userId: string,
  body: CimitStubUserCisRequest[],
): Promise<void> => {
  const response = await fetch(
    `${config.cimit.managementCimitUrl}/user/${userId}/cis`,
    {
      headers: {
        "x-api-key": config.cimit.managementCimitApiKey,
        "content-type": "application/json",
      },
      method: "POST",
      body: JSON.stringify(body),
    },
  );

  if (!response.ok) {
    throw new Error(`createUserCi request failed: ${response.statusText}`);
  }
};
