import { JourneyEvent, JourneyState, NestedJourneyMap } from "../types.js";
import { deepCloneJson } from "./deep-clone.js";
import { resolveVisibleEventTargets } from "./event-resolver.js";
import { RenderOptions } from "./options.js";

const mapTargetStateToExpandedState = (
  eventDef: JourneyEvent,
  subJourneyState: string,
  options: RenderOptions,
): void => {
  // Map target states to expanded states
  resolveVisibleEventTargets(eventDef, options).forEach((targetDef) => {
    if (targetDef.targetState && !targetDef.targetJourney) {
      targetDef.targetState = `${subJourneyState}/${targetDef.targetState}`;
    }
  });
};

// Expand out nested states
export const expandNestedJourneys = (
  journeyMap: Record<string, JourneyState>,
  subjourneys: Record<string, NestedJourneyMap>,
  options: RenderOptions,
): void => {
  Object.entries(journeyMap).forEach(([state, definition]) => {
    if (definition.nestedJourney && subjourneys[definition.nestedJourney]) {
      const subJourneyState = state;
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete journeyMap[subJourneyState];
      const subjourney = subjourneys[definition.nestedJourney];

      // Expand out each of the nested states
      Object.entries(subjourney.nestedJourneyStates).forEach(
        ([nestedState, nestedDefinition]) => {
          // Copy to avoid mutating different versions of the expanded definition
          const expandedDefinition = deepCloneJson(nestedDefinition);

          Object.entries(expandedDefinition.events || {}).forEach(
            ([evt, eventDef]) => {
              mapTargetStateToExpandedState(eventDef, subJourneyState, options);

              // Map exit events to targets in the parent definition
              const exitEvent = eventDef.exitEventToEmit;
              if (exitEvent) {
                delete eventDef.exitEventToEmit;
                if (definition.exitEvents?.[exitEvent]) {
                  Object.assign(eventDef, definition.exitEvents[exitEvent]);
                } else {
                  console.warn(
                    `Unhandled exit event from ${subJourneyState}:`,
                    exitEvent,
                  );
                  delete expandedDefinition.events?.[evt];
                }
              }
            },
          );

          journeyMap[`${subJourneyState}/${nestedState}`] = expandedDefinition;
        },
      );

      // Make a copy of the entry events to avoid mutating the original
      const entryEvents = deepCloneJson(subjourney.entryEvents);
      // Update entry events on other states to expanded states
      Object.entries(entryEvents).forEach(([entryEvent, entryEventDef]) => {
        mapTargetStateToExpandedState(entryEventDef, subJourneyState, options);

        Object.values(journeyMap).forEach((journeyDef) => {
          if (journeyDef.events?.[entryEvent]) {
            resolveVisibleEventTargets(journeyDef.events[entryEvent], options)
              .filter(
                (t) => t.targetState === subJourneyState && !t.targetEntryEvent,
              )
              .forEach((t) => {
                Object.assign(t, entryEventDef);
              });
          }

          // Resolve targets with a `targetEntryEvent` override
          Object.values(journeyDef.events ?? {}).forEach((eventDef) => {
            resolveVisibleEventTargets(eventDef, options)
              .filter(
                (t) =>
                  t.targetState === subJourneyState &&
                  t.targetEntryEvent === entryEvent,
              )
              .forEach((t) => {
                Object.assign(t, entryEventDef);
                delete t.targetEntryEvent;
              });
          });
        });
      });
    }
  });
};
