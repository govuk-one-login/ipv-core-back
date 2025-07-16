import {
  CriStubGenerateVcRequest,
  CriStubRequest,
  CriStubResponse,
} from "../types/cri-stub.js";
import config from "../config/config.js";

const STUB_CREDENTIAL_ISSUER_SUBDOMAINS: Record<string, string> = {
  ticf: "ticf",
  experianKbv: "experian-kbv-cri",
  dcmaw: "dcmaw-cri",
  address: "address-cri",
  fraud: "fraud-cri",
  ukPassport: "passport-cri",
  drivingLicence: "driving-license-cri",
  claimedIdentity: "claimed-identity-cri",
  f2f: "f2f-cri",
  nino: "nino-cri",
  dwpKbv: "dwp-kbv-cri",
  bav: "bav-cri",
};

export const buildCredentialIssuerUrl = (criId: string) =>
  `https://${STUB_CREDENTIAL_ISSUER_SUBDOMAINS[criId]}.stubs.account.gov.uk`;

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
    `${buildCredentialIssuerUrl(criId)}/credentials/generate`,
    {
      headers: {
        "x-api-key": config.credentialIssuers.generateCredentialApiKey,
        "content-type": "application/json",
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
