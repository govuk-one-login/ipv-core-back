import { JourneyTransition } from "../data/data.js";
import { SystemSettings } from "../helpers/options.js";

export interface TransitionsApiRequestBody {
  fromDate: string;
  toDate: string;
  ipvSessionId?: string;
  govukJourneyId?: string;
  environment: string;
}

export enum TargetEnvironment {
  PRODUCTION = "production",
  INTEGRATION = "integration",
  STAGING = "staging",
  BUILD = "build",
  SHARED_DEV = "shared-dev",
}

export const getSystemSettings = async (
  targetEnvironment: TargetEnvironment,
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
