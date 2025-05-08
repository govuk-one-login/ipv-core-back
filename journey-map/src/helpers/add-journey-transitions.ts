import { JourneyState } from "../types.js";
import { resolveAllTargets } from "./event-resolver.js";

// Add synthetic states for journey transitions
export const addJourneyTransitions = (
  states: Record<string, JourneyState>,
): void => {
  resolveAllTargets(states).forEach((target) => {
    if (target.targetJourney) {
      const transitionState = `${target.targetJourney}__${target.targetState}`;
      states[transitionState] = {
        response: {
          type: "journeyTransition",
          targetJourney: target.targetJourney,
          targetState: target.targetState,
        },
      };
      target.targetState = transitionState;
      delete target.targetJourney;
    }
  });
};
