import { JourneyTransition } from "../data/data.js";
import { SystemSettings } from "../helpers/options.js";

export interface TransitionsApiRequestBody {
  fromDate: string;
  toDate: string;
  ipvSessionId?: string;
  govukJourneyId?: string;
  environment: string;
}

export const getSystemSettings = async (): Promise<
  SystemSettings | undefined
> => {
  const response = await fetch("/system-settings");
  if (!response.ok) {
    console.warn(
      `Failed to fetch system settings from journey map server: ${response.statusText}`,
    );
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
    console.warn(
      `Failed to fetch journey transitions from journey map server: ${response.statusText}`,
    );
    return [];
  }
  return response.json();
};
