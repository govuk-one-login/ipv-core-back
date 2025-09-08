import { JourneyEngineResponse, JourneyResponse } from "./internal-api.js";
import { MfaResetResult, UserIdentity, VcJwtPayload } from "./external-api.js";
import { World as CucumberWorld } from "@cucumber/cucumber";
import { JSONWebKeySet, JWK } from "jose";
import { CriStubRequest } from "./cri-stub.js";

interface DidVerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: JWK;
}

export interface World extends CucumberWorld {
  // Journey properties
  userId: string;
  ipvSessionId: string | undefined;
  journeyId: string;
  featureSet: string | undefined;
  lastJourneyEngineResponse?: JourneyEngineResponse;
  lastCriRequest?: {
    redirectUrl: string;
    body: CriStubRequest;
  };
  clientOAuthSessionId?: string;

  // Identity proving results
  identity?: UserIdentity;
  vcs?: Record<string, VcJwtPayload>;

  // MFA reset results
  mfaResetResult?: MfaResetResult;

  // Healthcheck results
  healthCheckResult?: string;

  // JWKS result
  jwksResult?: JSONWebKeySet;

  // DID result
  didResult?: DidVerificationMethod[];

  // Latest error to assert against
  error?: Error;

  // Strategic app latent variables
  oauthState?: string;
  strategicAppPollResult?: JourneyResponse;
}
