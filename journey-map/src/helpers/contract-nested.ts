import { JourneyState } from "../types.js";

// Turn a nested journey state into a standard response state
export const contractNestedJourneys = (
  journeyMap: Record<string, JourneyState>,
): void => {
  Object.values(journeyMap).forEach((state) => {
    if (state.nestedJourney) {
      state.response = {
        type: "nestedJourney",
        nestedJourney: state.nestedJourney,
      };
      delete state.nestedJourney;
      state.events = state.exitEvents;
      delete state.exitEvents;
    }
  });
};
