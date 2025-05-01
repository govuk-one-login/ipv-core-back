import { JourneyEvent, JourneyState } from "../types.js";
import { RenderOptions } from "./options.js";

// Resolve all possible targets for a given event, with any options
export const resolveAllEventTargets = (
  eventDefinition: JourneyEvent,
): JourneyEvent[] => [
  eventDefinition,
  ...Object.values(eventDefinition.checkIfDisabled || {}).flatMap(
    resolveAllEventTargets,
  ),
  ...Object.values(eventDefinition.checkJourneyContext || {}).flatMap(
    resolveAllEventTargets,
  ),
  ...Object.values(eventDefinition.checkFeatureFlag || {}).flatMap(
    resolveAllEventTargets,
  ),
  ...Object.values(eventDefinition.checkMitigation || {}).flatMap(
    resolveAllEventTargets,
  ),
];

// Resolve all possible targets for a journey map, with any options
export const resolveAllTargets = (
  states: Record<string, JourneyState>,
): JourneyEvent[] =>
  Object.values(states).flatMap((state) => {
    return Object.values(state.events || state.exitEvents || {}).flatMap(
      resolveAllEventTargets,
    );
  });

// Resolve all visible targets for a given event, with the current options
// Multiple results are possible for mitigations and journey context routes
export const resolveVisibleEventTargets = (
  definition: JourneyEvent,
  options: RenderOptions,
  resolvedEventTargets?: JourneyEvent[],
): JourneyEvent[] => {
  const resolvedTargets = resolvedEventTargets || [];

  // Look for an override for disabled CRIs
  for (const cri of options.disabledCris) {
    if (definition.checkIfDisabled?.[cri]) {
      // Resolve target and propagate journeyContext and mitigation properties
      const resolved = definition.checkIfDisabled[cri];
      resolved.journeyContext = definition.journeyContext;
      resolved.mitigation = definition.mitigation;

      return resolveVisibleEventTargets(resolved, options, resolvedTargets);
    }
  }

  // Look for an override for journey contexts
  Object.entries(definition.checkJourneyContext || {}).forEach(
    ([journeyContext, resolved]) => {
      // Resolve target and set journeyContext property
      resolved.journeyContext = journeyContext;
      resolved.mitigation = definition.mitigation;

      const targets = resolveVisibleEventTargets(resolved, options);
      resolvedTargets.push(...targets);
    },
  );

  // Look for an override for feature flags
  for (const featureFlag of options.featureFlags) {
    if (definition.checkFeatureFlag?.[featureFlag]) {
      // Resolve target and propagate journeyContext and mitigation properties
      const resolved = definition.checkFeatureFlag[featureFlag];
      resolved.journeyContext = definition.journeyContext;
      resolved.mitigation = definition.mitigation;

      return resolveVisibleEventTargets(resolved, options, resolvedTargets);
    }
  }

  // Look for an override for mitigations
  Object.entries(definition.checkMitigation || {}).forEach(
    ([mitigation, resolved]) => {
      // Resolve target and set mitigation property
      resolved.mitigation = mitigation;
      resolved.journeyContext = definition.journeyContext;

      const targets = resolveVisibleEventTargets(resolved, options);
      resolvedTargets.push(...targets);
    },
  );

  return [...resolvedTargets, definition];
};
