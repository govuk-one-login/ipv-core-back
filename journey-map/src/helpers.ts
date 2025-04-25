import {
  JourneyEvent,
  JourneyMap,
  JourneyState,
  NestedJourneyMap,
} from "./types.js";

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

export interface JourneyMapOptions {
  disabledOptions: string[];
  featureFlagOptions: string[];
}

// Traverse the journey map to collect the available 'disabled' and 'featureFlag' options
export const getOptions = (
  journeyMaps: Record<string, JourneyMap>,
  nestedJourneys: Record<string, NestedJourneyMap>,
): JourneyMapOptions => {
  const disabledOptions: string[] = ["ticf"];
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

  return { disabledOptions, featureFlagOptions };
};

// Resolve all possible targets for a given event, given the current options
// Multiple results are given for mitigations and journey context routes
export const resolveEventTargets = (
  definition: JourneyEvent,
  formData: FormData,
  resolvedEventTargets?: JourneyEvent[],
): JourneyEvent[] => {
  const resolvedTargets = resolvedEventTargets || [];

  // Look for an override for disabled CRIs
  const disabledCris = formData.getAll("disabledCri") as string[];
  for (const cri of disabledCris) {
    if (definition.checkIfDisabled?.[cri]) {
      // Resolve target and propagate journeyContext and mitigation properties
      const resolved = definition.checkIfDisabled[cri];
      resolved.journeyContext = definition.journeyContext;
      resolved.mitigation = definition.mitigation;

      return resolveEventTargets(resolved, formData, resolvedTargets);
    }
  }

  // Look for an override for journey contexts
  Object.entries(definition.checkJourneyContext || {}).forEach(
    ([journeyContext, resolved]) => {
      // Resolve target and set journeyContext property
      resolved.journeyContext = journeyContext;
      resolved.mitigation = definition.mitigation;

      const targets = resolveEventTargets(resolved, formData);
      resolvedTargets.push(...targets);
    },
  );

  // Look for an override for feature flags
  const featureFlags = formData.getAll("featureFlag") as string[];
  for (const featureFlag of featureFlags) {
    if (definition.checkFeatureFlag?.[featureFlag]) {
      // Resolve target and propagate journeyContext and mitigation properties
      const resolved = definition.checkFeatureFlag[featureFlag];
      resolved.journeyContext = definition.journeyContext;
      resolved.mitigation = definition.mitigation;

      return resolveEventTargets(resolved, formData, resolvedTargets);
    }
  }

  // Look for an override for mitigations
  Object.entries(definition.checkMitigation || {}).forEach(
    ([mitigation, resolved]) => {
      // Resolve target and set mitigation property
      resolved.mitigation = mitigation;
      resolved.journeyContext = definition.journeyContext;

      const targets = resolveEventTargets(resolved, formData);
      resolvedTargets.push(...targets);
    },
  );

  return [...resolvedTargets, definition];
};

const addJourneyContextFromDefinition = (
  definition: JourneyEvent,
  journeyContexts: string[],
): void => {
  Object.values(definition.checkIfDisabled || {}).forEach((def) => {
    addJourneyContextFromDefinition(def, journeyContexts);
  });

  Object.entries(definition.checkJourneyContext || {}).forEach(([ctx, def]) => {
    if (!journeyContexts.includes(ctx)) {
      journeyContexts.push(ctx);
    }
    addJourneyContextFromDefinition(def, journeyContexts);
  });

  Object.values(definition.checkFeatureFlag || {}).forEach((def) => {
    addJourneyContextFromDefinition(def, journeyContexts);
  });
};

export const getJourneyContexts = (journeyStates: JourneyState[]): string[] => {
  const checkedJourneyContexts: string[] = [];
  Object.values(journeyStates).forEach((definition) => {
    const events = definition.events || definition.exitEvents || {};
    Object.values(events).forEach((def) => {
      addJourneyContextFromDefinition(def, checkedJourneyContexts);
    });
  });
  return checkedJourneyContexts;
};

export const getNestedJourneyStates = (
  nestedJourney: NestedJourneyMap,
): Record<string, JourneyState> => ({
  ...nestedJourney.nestedJourneyStates,
  // Create an entry state for each entry event
  ...Object.fromEntries(
    Object.entries(nestedJourney.entryEvents).map(([event, def]) => [
      `entry_${event}`.toUpperCase(),
      {
        entryEvent: event,
        events: { [event]: def },
      },
    ]),
  ),
});
