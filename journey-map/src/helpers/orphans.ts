import { JourneyState } from "../types.js";
import { resolveAllEventTargets } from "./event-resolver.js";

export const findOrphanStates = (
  journeyMap: Record<string, JourneyState>,
): string[] => {
  const targetedStates = [
    ...Object.values(journeyMap).flatMap((stateDefinition) => [
      ...Object.values(stateDefinition.events || {}).flatMap(
        resolveAllEventTargets,
      ),
      ...Object.values(stateDefinition.exitEvents || {}).flatMap(
        resolveAllEventTargets,
      ),
    ]),
  ];

  const uniqueTargetedStates = [...new Set(targetedStates)];

  return Object.keys(journeyMap).filter(
    (state) => !uniqueTargetedStates.includes(state),
  );
};
