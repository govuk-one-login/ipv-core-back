import { JourneyMap, JourneyState, NestedJourneyMap } from "../types.js";
import { deepCloneJson } from "./deep-clone.js";
import { resolveAllTargets } from "./event-resolver.js";
import { ENTRY_STATE_PREFIX, EXIT_STATE_PREFIX } from "../constants.js";

const buildSyntheticEntryStates = (
  nestedJourney: NestedJourneyMap,
): Record<string, JourneyState> =>
  Object.fromEntries(
    Object.entries(nestedJourney.entryEvents).map(([event, def]) => [
      `${ENTRY_STATE_PREFIX}${event.toUpperCase()}`,
      {
        entryEvent: event,
        events: { [event]: def },
      },
    ]),
  );

const buildSyntheticExitStates = (
  nestedJourney: NestedJourneyMap,
): Record<string, JourneyState> => {
  const states: Record<string, JourneyState> = {};

  resolveAllTargets(nestedJourney.nestedJourneyStates).forEach((target) => {
    if (target.exitEventToEmit) {
      const exitState = `${EXIT_STATE_PREFIX}${target.exitEventToEmit.toUpperCase()}`;
      target.targetState = exitState;
      states[exitState] = {
        exitEvent: target.exitEventToEmit,
      };
      delete target.exitEventToEmit;
    }
  });

  return states;
};

// Turns a nested journey map into a standard journey map with synthetic states for the entry events
export const getAsFullJourneyMap = (
  nestedJourney: NestedJourneyMap,
): JourneyMap => {
  const clone = deepCloneJson(nestedJourney);
  return {
    name: clone.name,
    description: clone.description,
    states: {
      ...clone.nestedJourneyStates,
      ...buildSyntheticEntryStates(clone),
      ...buildSyntheticExitStates(clone),
    },
  };
};
