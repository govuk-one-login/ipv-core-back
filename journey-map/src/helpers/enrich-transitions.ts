import { JourneyMap, NestedJourneyMap } from "../types.js";
import { JourneyTransition } from "../data/data.js";

export const enrichJourneyTransitionData = (
  journeyTransitions: JourneyTransition[],
  journeyMaps: Record<string, JourneyMap>,
  nestedJourneyMaps: Record<string, NestedJourneyMap>,
): JourneyTransition[] => {
  journeyTransitions.map((t) =>
    addNestedJourneyEntryEvent(t, journeyMaps, nestedJourneyMaps),
  );
  return journeyTransitions;
};

function addNestedJourneyEntryEvent(
  transition: JourneyTransition,
  journeyMaps: Record<string, JourneyMap>,
  nestedJourneyMaps: Record<string, NestedJourneyMap>,
) {
  let entryEvent;

  if (transition.from.includes("/")) {
    // This is a transition from a nested journey into another nested journey. The from field will contain something like:
    // HIGHEST_LEVEL_NESTED_JOURNEY/MID_LEVEL_NESTED_JOURNEY/LOWEST_LEVEL_NESTED_JOURNEY/STATE_IN_LOWEST_LEVEL
    const fromParts = transition.from.split("/");
    const fromState = fromParts[fromParts.length - 1];
    const lowestNestedJourney = fromParts[fromParts.length - 2];
    const fromJourneyMap = nestedJourneyMaps[lowestNestedJourney];

    entryEvent =
      fromJourneyMap?.nestedJourneyStates?.[fromState]?.events?.[
        transition.event
      ]?.targetEntryEvent;
  } else {
    entryEvent =
      journeyMaps[transition.fromJourney]?.states?.[transition.from]?.events?.[
        transition.event
      ]?.targetEntryEvent;
  }

  if (entryEvent) {
    transition.toEntryEvent = entryEvent;
  }
}
