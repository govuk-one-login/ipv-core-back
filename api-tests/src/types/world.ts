import { JourneyEngineResponse } from "./internal-api.js";
import { MfaResetResult, UserIdentity } from "./external-api.js";
import { World as CucumberWorld } from "@cucumber/cucumber";
import { VcJwtPayload } from "./external-api.js";
import { JSONWebKeySet } from "jose";
import { CriStubRequest } from "./cri-stub.js";

export interface World extends CucumberWorld {
  // Journey properties
  userId: string;
  ipvSessionId: string;
  journeyId: string;
  featureSet: string | undefined;
  lastJourneyEngineResponse?: JourneyEngineResponse;
  lastCriRequest?: {
    redirectUrl: string;
    body: CriStubRequest;
  };

  // Identity proving results
  identity?: UserIdentity;
  vcs?: Record<string, VcJwtPayload>;

  // MFA reset results
  mfaResetResult?: MfaResetResult;

  // Healthcheck results
  healthCheckResult?: boolean;

  // JWKS result
  jwksResult?: JSONWebKeySet;

  // Latest error to assert against
  error?: Error;
}
