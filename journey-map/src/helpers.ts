const addDefinitionOptions = (
  definition,
  disabledOptions,
  featureFlagOptions,
) => {
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
export const getOptions = (journeyMaps, nestedJourneys) => {
  const disabledOptions = ["ticf"];
  const featureFlagOptions = [];

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

export const resolveEventTargets = (
  definition,
  formData,
  resolvedEventTargets,
) => {
  const resolvedTargets = resolvedEventTargets || [];

  // Look for an override for disabled CRIs
  const disabledCris = formData.getAll("disabledCri");
  const disabledResolution = Object.keys(definition.checkIfDisabled || {}).find(
    (k) => disabledCris.includes(k),
  );
  if (disabledResolution) {
    // Resolve target and propagate journeyContext property
    const resolved = definition.checkIfDisabled[disabledResolution];
    resolved.journeyContext = definition.journeyContext;

    return resolveEventTargets(resolved, formData, resolvedTargets);
  }

  Object.keys(definition.checkJourneyContext || {}).forEach(
    (journeyContext) => {
      // Resolve target and set journeyContext property
      const resolved = definition.checkJourneyContext[journeyContext];
      resolved.journeyContext = journeyContext;

      const targets = resolveEventTargets(resolved, formData);
      resolvedTargets.push(...targets);
    },
  );

  Object.keys(definition.checkMitigation || {}).forEach((mitigation) => {
    const resolved = definition.checkMitigation[mitigation];
    resolved.mitigation = mitigation;

    const targets = resolveEventTargets(resolved, formData);
    resolvedTargets.push(...targets);
  });

  // Look for an override for feature flags
  const featureFlags = formData.getAll("featureFlag");
  const featureFlagResolution = Object.keys(
    definition.checkFeatureFlag || {},
  ).find((k) => featureFlags.includes(k));
  if (featureFlagResolution) {
    // Resolve target and propagate journeyContext property
    const resolved = definition.checkFeatureFlag[featureFlagResolution];
    resolved.journeyContext = definition.journeyContext;

    return resolveEventTargets(resolved, formData, resolvedTargets);
  }

  return [...resolvedTargets, definition];
};

const addJourneyContextFromDefinition = (definition, journeyContexts) => {
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

export const getJourneyContexts = (journeyStates) => {
  const checkedJourneyContexts = [];
  Object.values(journeyStates).forEach((definition) => {
    const events = definition.events || definition.exitEvents || {};
    Object.values(events).forEach((def) => {
      addJourneyContextFromDefinition(def, checkedJourneyContexts);
    });
  });
  return checkedJourneyContexts;
};

export const getNestedJourneyStates = (nestedJourney) => ({
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
