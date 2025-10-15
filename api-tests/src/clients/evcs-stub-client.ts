import config from "../config/config.js";
import {
  EvcsStoredIdentity,
  EvcsStubPostVcsRequest,
} from "../types/evcs-stub.js";

// If you need to edit this JWT note that the SIS stub does not check the signature, so any signature will do.
const STUB_CREDENTIAL_JWT =
  "eyJraWQiOiJ0ZXN0LXNpZ25pbmcta2V5IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOiJodHRwczovL3JldXNlLWlkZW50aXR5LmJ1aWxkLmFjY291bnQuZ292LnVrIiwic3ViIjoiNTExMjdhMTI3NWYxMDVkZmQzYmM1MjY0Yjk0NWZhMzEiLCJuYmYiOjE3NTE4OTQxNzEsImNyZWRlbnRpYWxzIjpbIk9sczNFNnhvV2RmdnAxSmJwQ3FLeUNVSDZhOFdEYnpVUXZVcEhTS0xySjJ4RDd0dGdPUnE4MTIxYkM0N2pkbG1XUGJDdzRaMEN1ekc1Nmg0bXNWNmpRIiwiby1OUDdFY2VGa1JxMEVZaGIydlROYmZWczZ2UkNRSjU4SUpYZURGVGxMZ2ZKWFNMdTdXeHktQV9CVXlYYnFsOGJBaS1IUzAzbk9hc0JlWWdjUEUwcVEiLCJnVDBvSW1hRFROQW5kVXMxQnpFTEZILVE5cWdncDI3bVFUYnZiSWFYaFVmSjZ2clJuQnVlX2pKSV84Mm9va1NSRmt1WlVFQUFsRklfXzJoRGIzb3pwdyIsIlAya0J6U1hOb2QwZmQ2MjNjOWJmTU1HQ0ZiSTRHamlYcWNLY1JrY1NKMU5YRmh0UXltSUxiOERCVFlKUjhuc29KX3N4TXM0UDYxcVZmbE1hbjBNdE5nIl0sImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkubG9jYWwuYWNjb3VudC5nb3YudWsiLCJjbGFpbXMiOnsiaHR0cHM6Ly92b2NhYi5hY2NvdW50Lmdvdi51ay92MS9jb3JlSWRlbnRpdHkiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NjUtMDctMDgifV19LCJodHRwczovL3ZvY2FiLmFjY291bnQuZ292LnVrL3YxL2FkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwiYnVpbGRpbmdOYW1lIjoiIiwiYnVpbGRpbmdOdW1iZXIiOiI4IiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJzdWJCdWlsZGluZ05hbWUiOiIiLCJ1cHJuIjoxMDAxMjAwMTIwNzcsInZhbGlkRnJvbSI6IjEwMDAtMDEtMDEifV0sImh0dHBzOi8vdm9jYWIuYWNjb3VudC5nb3YudWsvdjEvcGFzc3BvcnQiOlt7ImRvY3VtZW50TnVtYmVyIjoiMzIxNjU0OTg3IiwiZXhwaXJ5RGF0ZSI6IjIwMzAtMDEtMDEiLCJpY2FvSXNzdWVyQ29kZSI6IkdCUiJ9XX0sInZvdCI6IlAxIiwiaWF0IjoxNzUxODk0MTcxfQ.rTXoZ3c7xZIUBO4W2h__NWMwZfjWk5RcZskBWjH_KRldOgQ4KlmIBsakY456SsbplI6YfniAZo0EC5dVqsuMFw"; // pragma: allowlist secret

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
