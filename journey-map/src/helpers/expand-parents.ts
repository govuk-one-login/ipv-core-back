import { JourneyState } from "../types.js";
import { deepCloneJson } from "./deep-clone.js";

// Expand out parent states
// Will also search 'otherStates' (e.g. for nested journeys)
export const expandParents = (
  journeyStates: Record<string, JourneyState>,
  otherStates: Record<string, JourneyState>,
): void => {
  const parentStates: string[] = [];
  Object.entries(journeyStates).forEach(([state, definition]) => {
    if (definition.parent) {
      // Clone so each state gets an independent copy of the parent targets
      const parent = deepCloneJson(
        journeyStates[definition.parent] ?? otherStates[definition.parent],
      );
      if (!parent) {
        console.warn(`Missing parent ${definition.parent} of state ${state}`);
      } else {
        // Merge parent into existing definition
        const newDefinition = {
          ...parent,
          ...definition,
          events: {
            ...parent.events,
            ...definition.events,
          },
        };
        delete newDefinition.parent;
        journeyStates[state] = newDefinition;
        parentStates.push(definition.parent);
      }
    }
  });
  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
  parentStates.forEach((state) => delete journeyStates[state]);
};
