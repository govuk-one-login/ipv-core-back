import config from "../config/config.js";
import {
  EvcsStoredIdentity,
  EvcsStubPostVcsRequest,
} from "../types/evcs-stub.js";

const STUB_CREDENTIAL_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1cm46dXVpZDo5NjI4OTgxNS0wZTUyLTQ4MDAtOTZkZi0xZmY3ZGU5ODFjZDQiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3NDYwODkxNTEsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkuYnVpbGQuYWNjb3VudC5nb3YudWsiLCJhdWQiOiJodHRwczovL29yY2guc3R1YnMuYWNjb3VudC5nb3YudWsiLCJuYmYiOiIxNzc3NjI1MTUxIiwidm90IjoiUDIiLCJjcmVkZW50aWFscyI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5pSjkuZXlKemRXSWlPaUoxY200NmRYVnBaRG81TmpJNE9UZ3hOUzB3WlRVeUxUUTRNREF0T1Raa1ppMHhabVkzWkdVNU9ERmpaRFFpTENKaGRXUWlPaUpvZEhSd2N6b3ZMMmxrWlc1MGFYUjVMbUoxYVd4a0xtRmpZMjkxYm5RdVoyOTJMblZySWl3aWJtSm1Jam94TnpRMk1Ea3lOVGszTENKcGMzTWlPaUpvZEhSd2N6b3ZMMkZrWkhKbGMzTXRZM0pwTG5OMGRXSnpMbUZqWTI5MWJuUXVaMjkyTG5Wcklpd2lkbU1pT25zaWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJa0ZrWkhKbGMzTkRjbVZrWlc1MGFXRnNJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltRmtaSEpsYzNNaU9sdDdJbUZrWkhKbGMzTkRiM1Z1ZEhKNUlqb2lSMElpTENKaWRXbHNaR2x1WjA1aGJXVWlPaUlpTENKemRISmxaWFJPWVcxbElqb2lTRUZFVEVWWklGSlBRVVFpTENKd2IzTjBZV3hEYjJSbElqb2lRa0V5SURWQlFTSXNJbUoxYVd4a2FXNW5UblZ0WW1WeUlqb2lPQ0lzSW1Ga1pISmxjM05NYjJOaGJHbDBlU0k2SWtKQlZFZ2lMQ0oyWVd4cFpFWnliMjBpT2lJeU1EQXdMVEF4TFRBeEluMWRmWDBzSW1wMGFTSTZJblZ5YmpwMWRXbGtPbU13TlRWbFlXVmpMVEF5WmpVdE5EUTFOQzA1TnpreUxUWXlZemxqTldRM1l6QXdOeUo5LnhkSHlaVUV3d2k2VENpTTM4VXlOZEgtYkhkQjE0QnhtNm0xVWNuWE5SR1Z4cXFHR0R1cWgwODdsTDNtT0ZNd1BFVWxkTEU2TmVKOUI4dFZkSHJrUnlBIl0sImNsYWltcyI6W3siZXhwaXJ5RGF0ZSI6IjIwMzAtMDEtMDEiLCJpY2FvSXNzdWVyQ29kZSI6IkdCUiIsImRvY3VtZW50TnVtYmVyIjoiMzIxNjU0OTg3In0seyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IktFTk5FVEgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJERUNFUlFVRUlSQSJ9XX1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NS0wNy0wOCJ9XX1dfQ.DjY3mL3f1U1ehHILXz0ifAosUBCLH3HdAnqYX9YH4t7JdQjSECU885RJKUKZqE33vMvG0n-Ip1tULP7hkQ0R_A"; // pragma: allowlist secret

export const fetchEvcsAccessToken = async (userId: string): Promise<string> => {
  const response = await fetch(
    "https://mock.credential-store.dev.account.gov.uk/generate",
    {
      headers: {
        "Content-Type": "application/json",
      },
      method: "POST",
      body: JSON.stringify({
        sub: userId,
      }),
    },
  );

  if (!response.ok) {
    throw new Error("Failed to get evcs access token");
  }

  const body = await response.json();

  return body.token;
};

export const postCredentials = async (
  userId: string,
  body: EvcsStubPostVcsRequest,
): Promise<void> => {
  const response = await fetch(`${config.evcs.baseUrl}/vcs/${userId}`, {
    headers: {
      "x-api-key": config.evcs.apiKey,
      "content-type": "application/json",
    },
    method: "POST",
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`generateVc request failed: ${response.statusText}`);
  }
};

export const getStoredIdentity = async (
  userId: string,
): Promise<{ statusCode: number; storedIdentities?: EvcsStoredIdentity[] }> => {
  const response = await fetch(
    `${config.evcs.baseUrl}/management/stored-identity/${userId}`,
    {
      headers: {
        "x-api-key": config.evcs.apiKey,
      },
      method: "GET",
    },
  );

  if (response.status === 404) {
    return { statusCode: 404 };
  }

  if (!response.ok) {
    throw new Error(
      `Failed to get stored identity from EVCS: ${response.statusText}`,
    );
  }

  return {
    statusCode: response.status,
    storedIdentities: await response.json(),
  };
};

export const createStoredIdentity = async (userId: string, vot: string) => {
  const response = await fetch(
    `${config.evcs.baseUrl}/management/stored-identity/${userId}`,
    {
      headers: {
        "x-api-key": config.evcs.apiKey,
      },
      method: "POST",
      body: JSON.stringify({
        si: {
          // The jwt here can just be a stub JWT as we don't do anything with it.
          jwt: STUB_CREDENTIAL_JWT,
          vot,
        },
      }),
    },
  );

  if (!response.ok) {
    throw new Error(
      `Failed to create stored identity for user ${userId} in EVCS: ${response.statusText}`,
    );
  }
};
