import { JourneyTransition } from "../data/data.js";
import { SystemSettings } from "../helpers/options.js";

export interface TransitionsApiRequestBody {
  fromDate: string;
  toDate: string;
  ipvSessionId?: string;
  govukJourneyId?: string;
  environment: Environment;
}

export enum Environment {
  PRODUCTION = "production",
  INTEGRATION = "integration",
  STAGING = "staging",
  BUILD = "build",
  SHARED_DEV = "shared",
}

export const mapStringToEnvironment = (environment: string): Environment => {
  const normalized = environment.toLowerCase().trim();
  switch (normalized) {
    case "production":
      return Environment.PRODUCTION;
    case "integration":
      return Environment.INTEGRATION;
    case "staging":
      return Environment.STAGING;
    case "build":
      return Environment.BUILD;
    case "shared":
      return Environment.SHARED_DEV;
    default:
      alert(`Unknown environment: ${environment}. Fetching from production`);
      return Environment.PRODUCTION;
  }
};

export const getSystemSettings = async (
  targetEnvironment: Environment,
): Promise<SystemSettings | undefined> => {
  const response = await fetch(`/system-settings/${targetEnvironment}`);
  if (!response.ok) {
    console.warn(
      `Failed to fetch system settings from journey map server: ${response.statusText}`,
    );
    alert("Failed to fetch system settings.");
    return undefined;
  }
  return await response.json();
};

export const getJourneyTransitions = async (
  body: TransitionsApiRequestBody,
): Promise<JourneyTransition[]> => {
  const response = await fetch("/journey-transitions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorData = await response.json();
    alert(`${errorData?.message}`);
    return [];
  }
  return response.json();
};
