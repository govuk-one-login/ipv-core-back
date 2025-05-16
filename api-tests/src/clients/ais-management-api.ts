import config from "../config/config.js";

export const primeResponseForUser = async (
  userId: string,
  desiredResponse: string,
) => {
  const url = `${config.ais.managementAisUrl}/management/user/${userId}`;
  const requestBody = {
    intervention: desiredResponse,
  };

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
};
