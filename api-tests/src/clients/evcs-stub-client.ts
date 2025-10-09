import config from "../config/config.js";
import {
  EvcsStoredIdentity,
  EvcsStubPostVcsRequest,
} from "../types/evcs-stub.js";

// If you need to edit this JWT note that the SIS stub does not check the signature, so any signature will do.
const STUB_CREDENTIAL_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1cm46dXVpZDo5NjI4OTgxNS0wZTUyLTQ4MDAtOTZkZi0xZmY3ZGU5ODFjZDQiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3NDYwODkxNTEsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkuYnVpbGQuYWNjb3VudC5nb3YudWsiLCJhdWQiOiJodHRwczovL29yY2guc3R1YnMuYWNjb3VudC5nb3YudWsiLCJuYmYiOjE3Nzc2MjUxNTEsInZvdCI6IlAyIiwiY3JlZGVudGlhbHMiOlsiZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKRlV6STFOaUo5LmV5SnpkV0lpT2lKMWNtNDZkWFZwWkRvNU5qSTRPVGd4TlMwd1pUVXlMVFE0TURBdE9UWmtaaTB4Wm1ZM1pHVTVPREZqWkRRaUxDSmhkV1FpT2lKb2RIUndjem92TDJsa1pXNTBhWFI1TG1KMWFXeGtMbUZqWTI5MWJuUXVaMjkyTG5Wcklpd2libUptSWpveE56UTJNRGt5TlRrM0xDSnBjM01pT2lKb2RIUndjem92TDJGa1pISmxjM010WTNKcExuTjBkV0p6TG1GalkyOTFiblF1WjI5MkxuVnJJaXdpZG1NaU9uc2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWtGa1pISmxjM05EY21Wa1pXNTBhV0ZzSWwwc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbUZrWkhKbGMzTWlPbHQ3SW1Ga1pISmxjM05EYjNWdWRISjVJam9pUjBJaUxDSmlkV2xzWkdsdVowNWhiV1VpT2lJaUxDSnpkSEpsWlhST1lXMWxJam9pU0VGRVRFVlpJRkpQUVVRaUxDSndiM04wWVd4RGIyUmxJam9pUWtFeUlEVkJRU0lzSW1KMWFXeGthVzVuVG5WdFltVnlJam9pT0NJc0ltRmtaSEpsYzNOTWIyTmhiR2wwZVNJNklrSkJWRWdpTENKMllXeHBaRVp5YjIwaU9pSXlNREF3TFRBeExUQXhJbjFkZlgwc0ltcDBhU0k2SW5WeWJqcDFkV2xrT21Nd05UVmxZV1ZqTFRBeVpqVXRORFExTkMwNU56a3lMVFl5WXpsak5XUTNZekF3TnlKOS54ZEh5WlVFd3dpNlRDaU0zOFV5TmRILWJIZEIxNEJ4bTZtMVVjblhOUkdWeHFxR0dEdXFoMDg3bEwzbU9GTXdQRVVsZExFNk5lSjlCOHRWZEhya1J5QSJdLCJjbGFpbXMiOlt7ImV4cGlyeURhdGUiOiIyMDMwLTAxLTAxIiwiaWNhb0lzc3VlckNvZGUiOiJHQlIiLCJkb2N1bWVudE51bWJlciI6IjMyMTY1NDk4NyJ9LHsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NjUtMDctMDgifV19XX0.jEKott8ynODYRU4lN3XwpfaiRYPuMEyNvh5cYzTvouqhaEIjV8WUB-SxsshMAWPUKHnsMNmH913VIooPLRkfZQ"; // pragma: allowlist secret

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
