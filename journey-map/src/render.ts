import { getNestedJourneyStates, resolveEventTargets } from "./helpers.js";
import {
  JourneyEvent,
  JourneyMap,
  JourneyState,
  NestedJourneyMap,
} from "./types.js";

const topDownJourneys = ["INITIAL_JOURNEY_SELECTION"];
const errorJourneys = ["TECHNICAL_ERROR"];
const failureJourneys = ["INELIGIBLE", "FAILED"];

const JOURNEY_CONTEXT_TRANSITION_CLASSNAME = "journeyCtxTransition";
const MITIGATIONS_TRANSITION_CLASSNAME = "mitigationTransition";

// Simple deep clone - N.B. this will only work with pure JSON objects
const deepCloneJson = <T>(obj: T): T => JSON.parse(JSON.stringify(obj));

// Expand out parent states
// Will also search 'otherStates' (e.g. for nested journeys)
const expandParents = (
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

const mapTargetStateToExpandedState = (
  eventDef: JourneyEvent,
  subJourneyState: string,
  formData: FormData,
): void => {
  // Map target states to expanded states
  resolveEventTargets(eventDef, formData).forEach((targetDef) => {
    if (targetDef.targetState && !targetDef.targetJourney) {
      targetDef.targetState = `${subJourneyState}/${targetDef.targetState}`;
    }
  });
};

// Expand out nested states
const expandNestedJourneys = (
  journeyMap: Record<string, JourneyState>,
  subjourneys: Record<string, NestedJourneyMap>,
  formData: FormData,
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
              mapTargetStateToExpandedState(
                eventDef,
                subJourneyState,
                formData,
              );

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
        mapTargetStateToExpandedState(entryEventDef, subJourneyState, formData);

        Object.values(journeyMap).forEach((journeyDef) => {
          if (journeyDef.events?.[entryEvent]) {
            resolveEventTargets(journeyDef.events[entryEvent], formData)
              .filter(
                (t) => t.targetState === subJourneyState && !t.targetEntryEvent,
              )
              .forEach((t) => {
                Object.assign(t, entryEventDef);
              });
          }

          // Resolve targets with a `targetEntryEvent` override
          Object.values(journeyDef.events ?? {}).forEach((eventDef) => {
            resolveEventTargets(eventDef, formData)
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

interface TransitionsOutput {
  transitionsMermaid: string;
  states: string[];
}

// Render the transitions into mermaid, while tracking the states traced from the initial states
// This allows us to skip
const renderTransitions = (
  journeyStates: Record<string, JourneyState>,
  formData: FormData,
): TransitionsOutput => {
  // Initial states have no response or nested journey
  const initialStates = Object.keys(journeyStates).filter(
    (s) => !journeyStates[s].response && !journeyStates[s].nestedJourney,
  );

  const states = [...initialStates];
  const stateTransitions: string[] = [];

  for (const state of states) {
    const definition = journeyStates[state];
    const events = definition.events || definition.exitEvents || {};

    const eventsByTarget: Record<string, string[]> = {};
    Object.entries(events).forEach(([eventName, def]) => {
      const resolvedEventTargets = resolveEventTargets(def, formData);

      for (const resolvedTarget of resolvedEventTargets) {
        const {
          targetJourney,
          targetState,
          targetEntryEvent,
          exitEventToEmit,
          journeyContext,
          mitigation,
        } = resolvedTarget;

        const target = exitEventToEmit
          ? `exit_${exitEventToEmit}`.toUpperCase()
          : targetJourney
            ? `${targetJourney}__${targetState}`
            : targetState;

        if (
          errorJourneys.includes(targetJourney as string) &&
          !formData.getAll("otherOption").includes("includeErrors")
        ) {
          continue;
        }
        if (
          failureJourneys.includes(targetJourney as string) &&
          !formData.getAll("otherOption").includes("includeFailures")
        ) {
          continue;
        }

        if (!states.includes(target)) {
          states.push(target);
        }

        eventsByTarget[target] = eventsByTarget[target] || [];
        eventsByTarget[target].push(
          createTransitionLabel({
            eventName,
            targetEntryEvent,
            journeyContext,
            mitigation,
          }),
        );

        if (!journeyStates[target]) {
          if (targetJourney) {
            journeyStates[target] = {
              response: {
                type: "journeyTransition",
                targetJourney,
                targetState,
              },
            };
          } else if (exitEventToEmit) {
            journeyStates[target] = {
              exitEvent: exitEventToEmit,
            };
          } else {
            throw new Error(`Failed to resolve state ${target} from ${state}`);
          }
        }
      }
    });

    Object.entries(eventsByTarget).forEach(([target, eventNames]) => {
      stateTransitions.push(
        `    ${state}-->|${eventNames.join("\\n")}|${target}`,
      );
    });
  }

  return { transitionsMermaid: stateTransitions.join("\n"), states };
};

interface TransitionMeta {
  eventName: string;
  targetEntryEvent?: string;
  journeyContext?: string;
  mitigation?: string;
}

const createTransitionLabel = ({
  eventName,
  targetEntryEvent,
  journeyContext,
  mitigation,
}: TransitionMeta): string => {
  const eventLabel = `${eventName}${targetEntryEvent ? `/${targetEntryEvent}` : ""}`;

  const labelWithClass = (
    className: string,
    label: string,
    value: string,
  ): string =>
    `<span class="${className}">${eventLabel} - ${label}: ${value}</span>`;

  if (journeyContext) {
    return labelWithClass(
      JOURNEY_CONTEXT_TRANSITION_CLASSNAME,
      "journeyContext",
      journeyContext,
    );
  }

  if (mitigation) {
    return labelWithClass(
      MITIGATIONS_TRANSITION_CLASSNAME,
      "mitigation",
      mitigation,
    );
  }

  return eventLabel;
};

const renderClickHandler = (
  state: string,
  definition: JourneyState,
): string => {
  if (definition.nestedJourney) {
    definition.response = {
      type: "nestedJourney",
      nestedJourney: definition.nestedJourney,
    };
  }
  // Click handler serializes the definition to Base64-encoded JSON to avoid escaping issues
  return `    click ${state} call onStateClick(${JSON.stringify(state)}, ${btoa(JSON.stringify(definition.response ?? {}))})`;
};

const renderState = (state: string, definition: JourneyState): string => {
  // Special cases for nested journeys
  if (definition.nestedJourney) {
    return `    ${state}(${state}):::nested_journey`;
  }
  if (definition.exitEvent) {
    return `    ${state}[EXIT\\n${definition.exitEvent}]:::other`;
  }
  if (definition.entryEvent) {
    return `    ${state}[ENTRY\\n${definition.entryEvent}]:::other`;
  }

  // Types for basic nodes
  // process - response.type = process, response.lambda = <lambda>
  // page    - response.type = page, response.pageId = 'page-id'
  // cri     - response.type = cri,
  switch (definition.response?.type) {
    case "process":
      return `    ${state}(${state}\\n${definition.response.lambda}):::process`;
    case "page":
    case "error":
      return `    ${state}[${state}\\n${definition.response.pageId}]:::page`;
    case "cri": {
      const contextInfo = definition.response.context
        ? `\\n context: ${definition.response.context}`
        : "";
      return `    ${state}([${state}\\n${definition.response.criId}${contextInfo}]):::cri`;
    }
    case "journeyTransition": {
      const { targetJourney, targetState } = definition.response;
      return failureJourneys.includes(targetJourney as string) ||
        errorJourneys.includes(targetJourney as string)
        ? `    ${state}(${targetJourney}\\n${targetState}):::error_transition`
        : `    ${state}(${targetJourney}\\n${targetState}):::journey_transition`;
    }
    default:
      return `    ${state}:::other`;
  }
};

const renderStates = (
  journeyMapStates: Record<string, JourneyState>,
  states: string[],
): string => {
  const mermaids = states.flatMap((state) => {
    const definition = journeyMapStates[state];

    return [
      renderState(state, definition),
      renderClickHandler(state, definition),
    ];
  });

  return mermaids.join("\n");
};

const resolveAllPossibleEventTargets = (
  eventDefinition: JourneyEvent,
): string[] => [
  eventDefinition.targetState,
  ...Object.values(eventDefinition.checkIfDisabled || {}).flatMap(
    resolveAllPossibleEventTargets,
  ),
  ...Object.values(eventDefinition.checkFeatureFlag || {}).flatMap(
    resolveAllPossibleEventTargets,
  ),
];

const calcOrphanStates = (
  journeyMap: Record<string, JourneyState>,
): string[] => {
  const targetedStates = [
    ...Object.values(journeyMap).flatMap((stateDefinition) => [
      ...Object.values(stateDefinition.events || {}).flatMap(
        resolveAllPossibleEventTargets,
      ),
      ...Object.values(stateDefinition.exitEvents || {}).flatMap(
        resolveAllPossibleEventTargets,
      ),
    ]),
  ];

  const uniqueTargetedStates = [...new Set(targetedStates)];

  return Object.keys(journeyMap).filter(
    (state) => !uniqueTargetedStates.includes(state),
  );
};

const getMermaidGraph = (
  graphDirection: "TD" | "LR",
  statesMermaid: string,
  transitionsMermaid: string,
): string =>
  // These styles should be kept in sync with the key in style.css
  `graph ${graphDirection}
                classDef process fill:#ffa,stroke:#000;
                classDef page fill:#ae8,stroke:#000;
                classDef cri fill:#faf,stroke:#000;
                classDef journey_transition fill:#aaf,stroke:#000;
                classDef error_transition fill:#f99,stroke:#000;
                classDef other fill:#f3f2f1,stroke:#000;
                classDef nested_journey fill:#aaedff,stroke:#000;
            ${statesMermaid}
            ${transitionsMermaid}
            `;

export const render = (
  selectedJourney: string,
  journeyMap: JourneyMap,
  nestedJourneys: Record<string, NestedJourneyMap>,
  formData = new FormData(),
): string => {
  const isNestedJourney = selectedJourney in nestedJourneys;
  const direction = topDownJourneys.includes(selectedJourney) ? "TD" : "LR";

  // Copy to avoid mutating the input
  const journeyStates = deepCloneJson(
    isNestedJourney
      ? getNestedJourneyStates(nestedJourneys[selectedJourney])
      : journeyMap.states,
  );

  if (
    !isNestedJourney &&
    formData.getAll("otherOption").includes("expandNestedJourneys")
  ) {
    // Expand nested journeys first, to allow for two levels of nesting
    Object.values(nestedJourneys).forEach((nestedJourney) =>
      expandNestedJourneys(
        nestedJourney.nestedJourneyStates,
        nestedJourneys,
        formData,
      ),
    );
    expandNestedJourneys(journeyStates, nestedJourneys, formData);
  }

  expandParents(journeyStates, journeyMap.states);

  const { transitionsMermaid, states } = formData
    .getAll("otherOption")
    .includes("onlyOrphanStates")
    ? { transitionsMermaid: "", states: calcOrphanStates(journeyStates) }
    : renderTransitions(journeyStates, formData);

  const statesMermaid = renderStates(journeyStates, states);

  return getMermaidGraph(direction, statesMermaid, transitionsMermaid);
};
