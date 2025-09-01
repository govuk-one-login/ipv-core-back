import { JourneyEvent, JourneyMap, NestedJourneyMap } from "../types.js";

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

const addDefinitionOptions = (
  definition: JourneyEvent,
  disabledOptions: string[],
  featureFlagOptions: string[],
): void => {
  Object.entries(definition.checkIfDisabled || {}).forEach(([opt, def]) => {
    if (!disabledOptions.includes(opt)) {
      disabledOptions.push(opt);
    }
    addDefinitionOptions(def, disabledOptions, featureFlagOptions);
  });
  Object.entries(definition.checkFeatureFlag || {}).forEach(([opt, def]) => {
    if (!featureFlagOptions.includes(opt)) {
      featureFlagOptions.push(opt);
    }
    addDefinitionOptions(def, disabledOptions, featureFlagOptions);
  });
};

// Traverse the journey map to collect the available 'disabled' and 'featureFlag' options
export const getAvailableOptions = (
  journeyMaps: Record<string, JourneyMap>,
  nestedJourneys: Record<string, NestedJourneyMap>,
): AvailableOptions => {
  const disabledOptions: string[] = [];
  const featureFlagOptions: string[] = [];

  const states = [
    ...Object.values(journeyMaps).flatMap((journeyMap) =>
      Object.values(journeyMap.states),
    ),
    ...Object.values(nestedJourneys).flatMap((nestedJourney) =>
      Object.values(nestedJourney.nestedJourneyStates),
    ),
  ];

  states.forEach((definition) => {
    const events = definition.events || definition.exitEvents || {};
    Object.values(events).forEach((def) => {
      addDefinitionOptions(def, disabledOptions, featureFlagOptions);
    });
  });

  Object.values(nestedJourneys).forEach((nestedJourney) => {
    Object.values(nestedJourney.entryEvents).forEach((def) => {
      addDefinitionOptions(def, disabledOptions, featureFlagOptions);
    });
  });

  disabledOptions.sort();
  featureFlagOptions.sort();

  return { disabledCris: disabledOptions, featureFlags: featureFlagOptions };
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
