// import * as assert from "assert";
// import path from "path";
// import { BeforeAll } from "@cucumber/cucumber";
import { JSONWebKeySet } from "jose";
// import type { Validator } from "jsonschema";
import config from "../config/config.js";
import {
  MfaResetResult,
  TokenResponse,
  UserIdentity,
} from "../types/external-api.js";
// import { createValidator } from "../utils/schema-validator.js";

// let schemaValidator: Validator;
//
// BeforeAll(async () => {
//   try {
//     schemaValidator = await createValidator(
//       path.resolve(
//         import.meta.dirname,
//         "../../../openAPI/core-back-external.yaml",
//       ),
//     );
//   } catch (e) {
//     console.log(`Exception caught creating schema validator: ${e}`);
//     throw e;
//   }
// });
//
// const validateResponseSchema = async (
//   body: unknown,
//   schemaName: string,
// ): Promise<void> => {
//   const result = schemaValidator.validate(
//     body,
//     schemaValidator.schemas[`/${schemaName}`],
//   );
//
//   if (result.errors.length) {
//     const { property, message } = result.errors[0];
//     assert.fail(
//       `External API response did not match schema: ${property} ${message}`,
//     );
//   }
// };

export const exchangeCodeForToken = async (
  tokenExchangeBody: string,
): Promise<TokenResponse> => {
  const response = await fetch(`${config.core.externalApiUrl}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: tokenExchangeBody,
  });

  if (!response.ok) {
    throw new Error(
      `exchangeCodeForToken request failed: ${response.statusText}`,
    );
  }

  const body = await response.json();
  // await validateResponseSchema(body, "tokenResponse");

  return body;
};

export const getIdentity = async (
  tokenResponse: TokenResponse,
): Promise<UserIdentity> => {
  const response = await fetch(`${config.core.externalApiUrl}/user-identity`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${tokenResponse.access_token}`,
      "content-type": "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`getIdentity request failed: ${response.statusText}`);
  }

  const body = await response.json();
  // await validateResponseSchema(body, "userIdentityResponse");

  return body;
};

export const getMfaResetResult = async (
  tokenResponse: TokenResponse,
): Promise<MfaResetResult> => {
  const response = await fetch(`${config.core.externalApiUrl}/reverification`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${tokenResponse.access_token}`,
      "content-type": "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`getMfaResetResult request failed: ${response.statusText}`);
  }

  const body = await response.json();
  // await validateResponseSchema(body, "reverificationResponse");
  return body;
};

export const healthcheck = async (): Promise<string> => {
  const response = await fetch(`${config.core.externalApiUrl}/healthcheck`, {
    method: "GET",
  });

  if (!response.ok) {
    throw new Error(`healthcheck request failed: ${response.statusText}`);
  }

  const body = await response.json();
  // await validateResponseSchema(body, "healthcheckResponse");

  return body.healthcheck;
};

export const jwks = async (): Promise<JSONWebKeySet> => {
  const response = await fetch(
    `${config.core.externalApiUrl}/.well-known/jwks.json`,
    {
      method: "GET",
    },
  );

  if (!response.ok) {
    throw new Error(`jwks request failed: ${response.statusText}`);
  }

  const body = await response.json();
  // await validateResponseSchema(body, "jwksResponse");

  return body;
};
