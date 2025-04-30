import { JourneyEvent, JourneyState } from "../types.js";

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

export const getJourneyContexts = (
  journeyStates: Record<string, JourneyState>,
): string[] => {
  const checkedJourneyContexts: string[] = [];
  Object.values(journeyStates).forEach((definition) => {
    const events = definition.events || definition.exitEvents || {};
    Object.values(events).forEach((def) => {
      addJourneyContextFromDefinition(def, checkedJourneyContexts);
    });
  });
  return checkedJourneyContexts;
};
