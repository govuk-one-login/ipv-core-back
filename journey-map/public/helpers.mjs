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
