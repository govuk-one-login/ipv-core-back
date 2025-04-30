import { JourneyMap, NestedJourneyMap } from "../types.js";

// Turns a nested journey map into a standard journey map with synthetic states for the entry events
export const getAsFullJourneyMap = (
  nestedJourney: NestedJourneyMap,
): JourneyMap => ({
  name: nestedJourney.name,
  description: nestedJourney.description,
  states: {
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
  },
});
