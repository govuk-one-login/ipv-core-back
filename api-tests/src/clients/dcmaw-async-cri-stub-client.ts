import { CriStubGenerateDcmawAsyncVcScenarioRequest } from "../types/cri-stub.js";
import config from "../config/config.js";
import { generateDcmawAsyncVcCreationBodyFromScenario } from "../utils/request-body-generators.js";

const CRI_URL = "https://dcmaw-async.stubs.account.gov.uk";
const CRI_ID = "dcmawAsync";

export const enqueueVc = async (
  userId: string,
  scenario: string,
): Promise<string> => {
  const request = await generateDcmawAsyncVcCreationBodyFromScenario(
    userId,
    CRI_ID,
    scenario,
  );
  return await postToEnqueue(request);
};

export const enqueueVcFromDetails = async (
  userId: string,
  testUser: string,
  documentType: string,
  evidenceType: string,
  cis: string[] | undefined,
): Promise<string> => {
  return await postToEnqueue({
    user_id: userId,
    test_user: testUser,
    document_type: documentType,
    evidence_type: evidenceType,
    queue_name: config.asyncQueue.name,
    ci: cis,
  });
};

export const getOAuthState = async (userId: string): Promise<string> => {
  // If we post to the stub's Enqueue endpoint without specifying VC details it just returns the OAuth state to us.
  return await postToEnqueue({
    user_id: userId,
  });
};

export const generateVc = async (
  criId: string,
  body: CriStubGenerateDcmawAsyncVcScenarioRequest,
): Promise<string> => {
  const response = await fetch(`${CRI_URL}/management/generateVc`, {
    headers: {
      "x-api-key": config.credentialIssuers.generateCredentialApiKey,
      "content-type": "application/json",
    },
    method: "POST",
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`generateVc request failed: ${response.statusText}`);
  }

  return response.text();
};

export const enqueueError = async (
  userId: string,
  errorCode: string,
): Promise<void> => {
  const body = {
    user_id: userId,
    error_code: errorCode,
    queue_name: config.asyncQueue.name,
  };

  const response = await fetch(`${CRI_URL}/management/enqueueError`, {
    method: "POST",
    body: JSON.stringify(body),
    redirect: "manual",
  });

  if (response.status !== 201) {
    throw new Error(
      `DCMAW enqueue error request failed: ${await response.text()}`,
    );
  }

  return;
};

export const cleanUpDcmawState = async (userId: string): Promise<void> => {
  const response = await fetch(`${CRI_URL}/management/cleanupDcmawState`, {
    method: "POST",
    body: JSON.stringify({
      user_id: userId,
    }),
    redirect: "manual",
  });

  if (response.status !== 200) {
    throw new Error(
      `DCMAW session state cleanup request failed: ${response.statusText}`,
    );
  }
};

const postToEnqueue = async (body: object) => {
  const response = await fetch(`${CRI_URL}/management/enqueueVc`, {
    method: "POST",
    body: JSON.stringify(body),
    redirect: "manual",
  });

  const responsePayload = await response.json();
  if (response.status !== 201) {
    throw new Error(
      `DCMAW enqueue VC request failed: ${JSON.stringify(responsePayload)}`,
    );
  }

  if (
    !responsePayload.oauthState ||
    typeof responsePayload.oauthState !== "string"
  ) {
    throw new Error(
      `DCMAW enqueue VC request did not return a string oauthState: ${responsePayload.oauthState}`,
    );
  }
  return responsePayload.oauthState;
};
