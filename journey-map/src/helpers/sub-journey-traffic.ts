import { JourneyEvent, JourneyMap, JourneyState } from "../types.js";
import { JourneyTransition } from "../data/data.js";
import { FIRST_JOURNEYS } from "../constants.js";

export const getTransitionCountFromSubJourneyStateToTargetState = (
  journeyStates: Record<string, JourneyState>,
  journeyMapName: string,
  journeyMaps: Record<string, JourneyMap>,
  journeyTransitionsTraffic: JourneyTransition[],
  sourceState: string,
  targetState: string,
  allTargetsFromState: string[],
): number => {
  const sourceStateDefinition = journeyStates[sourceState];
  const targetStateDefinition = journeyStates[targetState];

  return journeyTransitionsTraffic
    .filter((transition) => {
      // Handle transitions if the sourceState is a basic state and the targetState is to a new sub-journey
      if (targetState.includes("__")) {
        const [targetSubJourney, entryState] = targetState.split("__", 2);
        return (
          transition.fromJourney === journeyMapName &&
          transition.from.split("/")[0] === sourceState && // We split this by "/" to also handle transitions to/from a nested journey entry state
          transition.toJourney === targetSubJourney &&
          // We want to compare to all possible targetStates from the entryState
          // as the entryState can also have different targetStates from
          // different conditional checks
          getAllTargetStatesFromEntryEvent(
            journeyMaps[targetSubJourney].states[entryState].events?.next,
          ).includes(transition.to.split("/")[0])
        );
      }

      // Handle transitions if the sourceState is a nested journey state
      if (sourceStateDefinition.response?.type === "nestedJourney") {
        return (
          transition.fromJourney === journeyMapName &&
          transition.from.split("/")[0] === sourceState &&
          transition.toJourney === journeyMapName &&
          (targetStateDefinition.response?.type === "nestedJourney"
            ? transition.to.split("/")[0] === targetState
            : transition.to === targetState)
        );
      }

      // Handle transitions if the sourceState is a sub-journey entry state
      // We check against all targets for the entry state as the current
      // targetState could be from a conditional
      if (
        !sourceStateDefinition.response &&
        allTargetsFromState.includes(targetState)
      ) {
        return (
          // Sub-journeys which act as the first sub-journey a user goes through will have entry states
          // which map directly to a transition from that journey map and not from other sub-journeys.
          // Whereas, for non-entry sub-journey maps, their entry states will transition
          // from other sub-journeys and so we don't need to match `fromJourney` and `from`
          // exactly.
          (FIRST_JOURNEYS.includes(journeyMapName)
            ? transition.fromJourney === journeyMapName &&
              transition.from === sourceState
            : transition.fromJourney !== journeyMapName) &&
          transition.toJourney === journeyMapName &&
          transition.to.split("/")[0] === targetState
        );
      }

      // Handle all other transitions internal to the sub-journey
      return (
        transition.fromJourney === journeyMapName &&
        transition.from === sourceState &&
        transition.toJourney === journeyMapName &&
        transition.to.split("/")[0] === targetState
      );
    })
    .reduce((acc, t) => acc + t.count, 0);
};

const getAllTargetStatesFromEntryEvent = (
  nextEvent: JourneyEvent | undefined,
): string[] => {
  if (!nextEvent) {
    return [];
  }

  const allTargetStates: string[] = [];
  const findAndStoreTargetState = (current: JourneyEvent) => {
    for (const [key, value] of Object.entries(current)) {
      if (
        key === "targetState" &&
        typeof value === "string" &&
        !allTargetStates.includes(value)
      ) {
        allTargetStates.push(value);
      } else if (value && typeof value === "object") {
        findAndStoreTargetState(value);
      }
    }
  };

  findAndStoreTargetState(nextEvent);
  return allTargetStates;
};
