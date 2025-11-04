import { JourneyMap, JourneyState } from "../types.js";
import { JourneyTransition } from "../data/data.js";

export const getTransitionCountFromSubJourneyStateToTargetState = (
  journeyStates: Record<string, JourneyState>,
  journeyMapName: string,
  journeyMaps: Record<string, JourneyMap>,
  journeyTransitionsTraffic: JourneyTransition[],
  sourceState: string,
  targetState: string,
): number => {
  const sourceStateDefinition = journeyStates[sourceState];
  const targetStateDefinition = journeyStates[targetState];

  return journeyTransitionsTraffic
    .filter((transition) => {
      // Handle transitions if the sourceState is a nested journey entry state
      if (sourceStateDefinition.response?.type === "nestedJourney") {
        if (targetStateDefinition.response?.type === "nestedJourney") {
          return (
            transition.fromJourney === journeyMapName &&
            transition.from.split("/")[0] === sourceState &&
            transition.toJourney === journeyMapName &&
            transition.to.split("/")[0] === targetState
          );
        }
        return (
          transition.fromJourney === journeyMapName &&
          transition.from.split("/")[0] === sourceState &&
          transition.toJourney === journeyMapName &&
          transition.to === targetState
        );
      }

      // Handle transitions if the sourceState is a sub-journey entry state
      // Sub-journey entry states do not have a `response` and will always have a "next" event
      if (
        !sourceStateDefinition.response &&
        sourceStateDefinition.events?.next?.targetState === targetState
      ) {
        return (
          transition.toJourney == journeyMapName &&
          transition.to === targetState
        );
      }

      // Handle transitions if the sourceState is a basic state and the targetState is to a new sub-journey
      if (targetState.includes("__")) {
        const [targetSubjourney, entryState] = targetState.split("__", 2);
        const actualTargetState =
          journeyMaps[targetSubjourney].states[entryState].events?.next
            .targetState;
        return (
          transition.fromJourney === journeyMapName &&
          transition.from === sourceState &&
          transition.toJourney === targetSubjourney &&
          transition.to === actualTargetState
        );
      }

      // Handle all other transitions internal to the sub-journey
      return (
        transition.fromJourney === journeyMapName &&
        transition.from === sourceState &&
        transition.toJourney === journeyMapName &&
        transition.to.split("/")[0] === targetState // We split this by "/" to also handle transitions from basic states where the targetState is a nested journey
      );
    })
    .reduce((acc, t) => acc + t.count, 0);
};
