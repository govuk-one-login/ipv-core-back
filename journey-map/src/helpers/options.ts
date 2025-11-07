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

export const parseOptions = (
  formData: FormData,
  journeyMapForm: FormData,
): RenderOptions => ({
  disabledCris: formData.getAll("disabledCri") as string[],
  featureFlags: formData.getAll("featureFlag") as string[],
  includeErrors: journeyMapForm.getAll("otherOption").includes("includeErrors"),
  includeFailures: journeyMapForm
    .getAll("otherOption")
    .includes("includeFailures"),
  expandNestedJourneys: journeyMapForm
    .getAll("otherOption")
    .includes("expandNestedJourneys"),
  onlyOrphanStates: journeyMapForm
    .getAll("otherOption")
    .includes("onlyOrphanStates"),
});
