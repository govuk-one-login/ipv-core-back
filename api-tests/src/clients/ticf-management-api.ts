import config from "../config/config.js";
import { DataTable } from "@cucumber/cucumber";
import { TicfManagementParameters } from "../types/ticf-management-api.js";
import { getRandomString } from "../utils/random-string-generator.js";

export const parseTableForTicfManagementParameters = (table: DataTable) => {
  const rowsHash = table.rowsHash();
  const responseDelay = parseInt(rowsHash.responseDelay) || 0;
  const cis = rowsHash.cis && rowsHash.cis.split(",");
  const interventionCode = rowsHash.interventionCode;
  const statusCode = parseInt(rowsHash.statusCode) || 200;

  return {
    evidence: {
      ci: cis || undefined,
      intervention: interventionCode ? { interventionCode } : undefined,
      type: rowsHash.type || "RiskAssessment",
      txn: rowsHash.txn === "" ? undefined : getRandomString(16),
    },
    responseDelay,
    statusCode,
  };
};

export const postUserToTicfManagementApi = async (
  userId: string,
  parsedTicfManagementParameters: TicfManagementParameters,
) => {
  const url = `${config.ticf.managementTicfUrl}/management/user/${userId}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "x-api-key": config.ticf.managementTicfApiKey,
      "content-type": "application/json",
    },
    body: JSON.stringify(parsedTicfManagementParameters),
  });

  if (!response.ok) {
    throw new Error(
      `TICF Management API request failed: ${response.statusText}`,
    );
  }
};
