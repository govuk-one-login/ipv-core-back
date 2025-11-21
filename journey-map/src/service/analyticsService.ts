import { JourneyTransition } from "../data/data.js";
import { SystemSettings } from "../helpers/options.js";
import { Environment } from "../constants.js";

export interface TransitionsApiRequestBody {
  fromDate: string;
  toDate: string;
  ipvSessionId?: string;
  govukJourneyId?: string;
  environment: Environment;
}

export const mapStringToEnvironment = (environment: string): Environment => {
  const normalized = environment.toUpperCase().trim();
  const env = Environment[normalized as keyof typeof Environment];
  if (!env) {
    alert(`Unknown environment: ${environment}. Fetching from production`);
    return Environment.PRODUCTION;
  }
  return env;
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
