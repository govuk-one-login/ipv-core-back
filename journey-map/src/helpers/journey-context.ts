import { JourneyState } from "../types.js";
import { resolveAllTargets } from "./event-resolver.js";

export const getJourneyContexts = (
  journeyStates: Record<string, JourneyState>,
): string[] => {
  return [
    ...new Set(
      resolveAllTargets(journeyStates).flatMap((target) =>
        Object.keys(target.checkJourneyContext ?? {}),
      ),
    ),
  ];
};
