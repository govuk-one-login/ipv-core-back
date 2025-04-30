import { JourneyState, NestedJourneyMap } from "../types.js";

// Turns a nested journey map into a standard journey map with synthetic states for the entry events
export const getNestedJourneyStates = (
  nestedJourney: NestedJourneyMap,
): Record<string, JourneyState> => ({
  ...nestedJourney.nestedJourneyStates,
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
