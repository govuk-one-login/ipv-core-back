import { JourneyState } from "../types.js";
import { resolveAllTargets } from "./event-resolver.js";

export const findOrphanStates = (
  states: Record<string, JourneyState>,
): string[] => {
  const targetedStates = resolveAllTargets(states)
    .filter((target) => target.targetState && !target.targetJourney)
    .map((target) => target.targetState);

  return Object.keys(states).filter((state) => !targetedStates.includes(state));
};
