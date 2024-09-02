import config from "../config/config.js";
import { DataTable } from "@cucumber/cucumber";
import { getRandomString } from "../utils/random-string-generator.js";

export const parseTableForTicfManagementParameters = (table: DataTable) => {
  const rowsHash = table.rowsHash();
  const responseDelay = parseInt(rowsHash.responseDelay) || 0;
  const cis = rowsHash.cis && rowsHash.cis.split(",");

  return {
    cis: cis || [],
    responseDelay,
    type: rowsHash.type,
    txn: rowsHash.txn ?? undefined,
  };
};

export const postUserToTicfManagementApi = async (
  userId: string,
  cis: string[] | undefined,
  type: string,
  responseDelay: number,
  txn: string | undefined,
) => {
  const response = await fetch(
    `${config.ticf.managementTicfUrl}/management/user/${userId}`,
    {
      method: "POST",
      headers: {
        "x-api-key": config.ticf.managementTicfApiKey,
      },
      body: JSON.stringify({
        type: type || "RiskAssessment",
        ci: cis,
        txn: txn ?? getRandomString(16),
        responseDelay,
      }),
    },
  );

  if (!response.ok) {
    throw new Error(
      `TICF Management API request failed: ${response.statusText}`,
    );
  }
};
