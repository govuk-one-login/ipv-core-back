export interface AvailableOptions {
  disabledCris: string[];
  featureFlags: string[];
}

export interface RenderOptions extends AvailableOptions {
  includeErrors: boolean;
  includeFailures: boolean;
  expandNestedJourneys: boolean;
  onlyOrphanStates: boolean;
}

export interface SystemSettings {
  featureFlagStatuses: Record<string, boolean>;
  criStatuses: Record<string, boolean>;
}

export interface TransitionsApiRequestBody {
  fromDate: string;
  toDate: string;
  sessionId: string;
  journeyId: string;
}

export interface TransitionsApiSettings {
  isEnabled: boolean;
  body: TransitionsApiRequestBody;
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

export const parseOptions = (formData: FormData): RenderOptions => ({
  disabledCris: formData.getAll("disabledCri") as string[],
  featureFlags: formData.getAll("featureFlag") as string[],
  includeErrors: formData.getAll("otherOption").includes("includeErrors"),
  includeFailures: formData.getAll("otherOption").includes("includeFailures"),
  expandNestedJourneys: formData
    .getAll("otherOption")
    .includes("expandNestedJourneys"),
  onlyOrphanStates: formData.getAll("otherOption").includes("onlyOrphanStates"),
});

const addSystemTimeZone = (dateTimeStr: string): string => {
  const date = new Date(dateTimeStr);
  const offset = date.getTimezoneOffset();
  const sign = offset > 0 ? "-" : "+";
  const absOffset = Math.abs(offset);
  const offsetHours = String(Math.floor(absOffset / 60)).padStart(2, "0");
  const offsetMinutes = String(absOffset % 60).padStart(2, "0");
  return `${dateTimeStr}${sign}${offsetHours}:${offsetMinutes}`;
};

export const parseApiSettings = (
  formData: FormData,
): TransitionsApiSettings => {
  const selection = formData.get("sessionJourneySelection") as
    | "journey"
    | "session";
  const typedInput = (formData.get("journeySession") as string) ?? "";

  return {
    isEnabled: formData.getAll("isEnabled").includes("enableTraffic"),
    body: {
      fromDate: addSystemTimeZone(formData.get("fromDate") as string),
      toDate: addSystemTimeZone(formData.get("toDate") as string),
      sessionId: selection === "session" ? typedInput : "",
      journeyId: selection === "journey" ? typedInput : "",
    },
  };
};
