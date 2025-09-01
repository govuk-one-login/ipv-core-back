import config from "../config/config.js";

interface AisManagementRequestBody {
  intervention: string;
  statusCode?: number;
}

export const primeResponseForUser = async (
  userId: string,
  desiredResponse: AisValidResponseTypes,
) => {
  const requestBody: AisManagementRequestBody = {
    intervention: AisValidResponseTypes[desiredResponse],
  };

  await sendManagementRequest(userId, requestBody);
};

export const primeErrorResponseForUser = async (
  userId: string,
  statusCode: number,
) => {
  const requestBody: AisManagementRequestBody = {
    intervention:
      AisValidResponseTypes[AisValidResponseTypes.AIS_NO_INTERVENTION],
    statusCode: statusCode,
  };

  await sendManagementRequest(userId, requestBody);
};

async function sendManagementRequest(
  userId: string,
  requestBody: AisManagementRequestBody,
) {
  const url = `${config.ais.managementAisUrl}/management/user/${userId}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(
      `AIS Management API request failed: ${response.statusText}`,
    );
  }
}

export enum AisValidResponseTypes {
  AIS_NO_INTERVENTION,
  AIS_ACCOUNT_SUSPENDED,
  AIS_ACCOUNT_UNSUSPENDED,
  AIS_ACCOUNT_BLOCKED,
  AIS_ACCOUNT_UNBLOCKED,
  AIS_FORCED_USER_PASSWORD_RESET,
  AIS_FORCED_USER_IDENTITY_VERIFY,
  AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY,
}
