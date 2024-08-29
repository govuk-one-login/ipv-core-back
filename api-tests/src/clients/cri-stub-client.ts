import { CriStubRequest, CriStubResponse } from "../types/cri-stub.js";

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
