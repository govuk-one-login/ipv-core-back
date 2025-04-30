// Expand out parent states

import { JourneyState } from "../types.js";

// Will also search 'otherStates' (e.g. for nested journeys)
export const expandParents = (
  journeyStates: Record<string, JourneyState>,
  otherStates: Record<string, JourneyState>,
): void => {
  const parentStates: string[] = [];
  Object.entries(journeyStates).forEach(([state, definition]) => {
    if (definition.parent) {
      const parent =
        journeyStates[definition.parent] ?? otherStates[definition.parent];
      if (!parent) {
        console.warn(`Missing parent ${definition.parent} of state ${state}`);
      } else {
        definition.events = {
          ...parent.events,
          ...definition.events,
        };
        journeyStates[state] = { ...parent, ...definition };
        parentStates.push(definition.parent);
      }
    }
  });
  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
  parentStates.forEach((state) => delete journeyStates[state]);
};
