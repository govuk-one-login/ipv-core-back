import {
  CriStubGenerateVcRequest,
  CriStubRequest,
  CriStubResponse,
} from "../types/cri-stub.js";
import config from "../config/config.js";

export const callHeadlessApi = async (
  redirectUrl: string,
  body: CriStubRequest,
): Promise<CriStubResponse> => {
  const criStubResponse = await fetch(
    `${new URL(redirectUrl).origin}/api/authorize`,
    {
      method: "POST",
      body: JSON.stringify(body),
      redirect: "manual",
    },
  );

  if (criStubResponse.status !== 200) {
    throw new Error(
      `callHeadlessApi request failed: ${criStubResponse.statusText}`,
    );
  }

  return criStubResponse.json();
};

export const generateVc = async (
  criId: string,
  body: CriStubGenerateVcRequest,
): Promise<string> => {
  const response = await fetch(
    `https://${criId}-cri.stubs.account.gov.uk/credentials/generate`,
    {
      headers: {
        "x-api-key": config.credentialIssuers.generateCredentialApiKey,
      },
      method: "POST",
      body: JSON.stringify(body),
    },
  );

  if (!response.ok) {
    throw new Error(`generateVc request failed: ${response.statusText}`);
  }

  return response.text();
};
