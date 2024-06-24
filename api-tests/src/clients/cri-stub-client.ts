import { CriStubResponse } from "../interfaces/cri-stub-response.js";
import { CriStubRequest } from "../interfaces/cri-stub-request.js";

export const callHeadlessApi = async (
  redirectUrl: string,
  body: CriStubRequest,
): Promise<CriStubResponse> => {
  const criStubResponse = await fetch(
    new URL(redirectUrl).origin + "/api/authorize",
    {
      method: "POST",
      body: JSON.stringify(body),
      redirect: "manual",
    },
  );

  if (!(criStubResponse.status === 302)) {
    throw new Error(
      "callHeadlessApi request failed: " + criStubResponse.statusText,
    );
  }

  return {
    redirectUri: criStubResponse.headers.get("location") as string,
  };
};
