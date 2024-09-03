import config from "../config/config.js";
import { DataTable } from "@cucumber/cucumber";

export const parseTableForTicfManagementParameters = (table: DataTable) => {
  const rowsHash = table.rowsHash();
  const responseDelay = parseInt(rowsHash.responseDelay) || 0;
  const cis = rowsHash.cis && rowsHash.cis.split(",");

  return {
    cis: cis || [],
    responseDelay,
    type: rowsHash.type,
    txn: rowsHash.txn ?? undefined,
    statusCode: rowsHash.statusCode,
  };
};

export const postUserToTicfManagementApi = async (
  userId: string,
  cis: string[] | undefined,
  type: string,
  responseDelay: number,
  txn: string | undefined,
  statusCode: string | undefined,
) => {
  const statusCodeUrlParam = statusCode ? `/statuscode/${statusCode}` : "";
  const url = `${config.ticf.managementTicfUrl}/management/user/${userId}${statusCodeUrlParam}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "x-api-key": config.ticf.managementTicfApiKey,
    },
    body: JSON.stringify({
      type: type || "RiskAssessment",
      ci: cis,
      txn,
      responseDelay,
    }),
  });

  if (!response.ok) {
    throw new Error(
      `TICF Management API request failed: ${response.statusText}`,
    );
  }
};
