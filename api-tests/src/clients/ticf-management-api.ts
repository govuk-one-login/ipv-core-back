import config from "../config/config.js";
import { DataTable } from "@cucumber/cucumber";
import { TicfManagementParameters } from "../types/ticf-management-api.js";
import { getRandomString } from "../utils/random-string-generator.js";

export const parseTableForTicfManagementParameters = (table: DataTable) => {
  const rowsHash = table.rowsHash();
  const responseDelay = parseInt(rowsHash.responseDelay) || 0;
  const cis = rowsHash.cis && rowsHash.cis.split(",");

  return {
    ci: cis || undefined,
    responseDelay,
    type: rowsHash.type || "RiskAssessment",
    txn: rowsHash.txn === "" ? undefined : getRandomString(16),
    statusCode: rowsHash.statusCode,
  };
};

export const postUserToTicfManagementApi = async (
  userId: string,
  parsedTicfManagementParameters: {
    statusCode: string;
  } & TicfManagementParameters,
) => {
  const { statusCode } = parsedTicfManagementParameters;
  const statusCodeUrlParam = statusCode ? `/statuscode/${statusCode}` : "";
  const url = `${config.ticf.managementTicfUrl}/management/user/${userId}${statusCodeUrlParam}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "x-api-key": config.ticf.managementTicfApiKey,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      ...parsedTicfManagementParameters,
      statusCode: undefined,
    }),
  });

  if (!response.ok) {
    throw new Error(
      `TICF Management API request failed: ${response.statusText}`,
    );
  }
};
