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
