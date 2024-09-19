const addDefinitionOptions = (definition, disabledOptions, featureFlagOptions) => {
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
export const getOptions = (journeyMaps) => {
    const disabledOptions = ['ticf'];
    const featureFlagOptions = [];

    Object.values(journeyMaps).forEach((journeyMap) => {
        Object.values(journeyMap.states).forEach((definition) => {
            const events = definition.events || definition.exitEvents || {};
            Object.values(events).forEach((def) => {
                addDefinitionOptions(def, disabledOptions, featureFlagOptions);
            });
        });
    });

    disabledOptions.sort();
    featureFlagOptions.sort();

    return { disabledOptions, featureFlagOptions };
};

export const resolveEventTargets = (definition, resolvedEventTargets, formData) => {
    const resolvedTargets = resolvedEventTargets || [];

    // Look for an override for disabled CRIs
    const disabledCris = formData.getAll('disabledCri');
    const disabledResolution = Object.keys(definition.checkIfDisabled || {}).find((k) => disabledCris.includes(k));
    if (disabledResolution) {
        return resolveEventTargets(
            {...definition.checkIfDisabled[disabledResolution], journeyContext: definition.journeyContext},
            resolvedTargets,
            formData);
    }

    const journeyContext = Object.keys(definition.checkJourneyContext || {})[0];
    if (journeyContext) {
        return resolveEventTargets(
            {...definition.checkJourneyContext[journeyContext], journeyContext},
            [...resolvedTargets, definition],
            formData)
    }

    // Look for an override for feature flags
    const featureFlags = formData.getAll('featureFlag');
    const featureFlagResolution = Object.keys(definition.checkFeatureFlag || {}).find((k) => featureFlags.includes(k));
    if (featureFlagResolution) {
        return resolveEventTargets(
            {...definition.checkFeatureFlag[featureFlagResolution], journeyContext: definition.journeyContext},
            resolvedTargets,
            formData);
    }

    return [...resolvedTargets, definition];
}
