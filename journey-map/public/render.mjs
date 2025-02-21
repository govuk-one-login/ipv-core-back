import { getNestedJourneyStates, resolveEventTargets } from "./helpers.mjs";
import { visits } from "./visits.mjs";

const topDownJourneys = ["INITIAL_JOURNEY_SELECTION"];
const errorJourneys = ["TECHNICAL_ERROR"];
const failureJourneys = ["INELIGIBLE", "FAILED"];

// Expand out parent states
// Will also search 'otherStates' (e.g. for nested journeys)
const expandParents = (journeyStates, otherStates) => {
  const parentStates = [];
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
  parentStates.forEach((state) => delete journeyStates[state]);
};

const mapTargetStateToExpandedState = (eventDef, subJourneyState, formData) => {
  // Map target states to expanded states
  resolveEventTargets(eventDef, formData).forEach((targetDef) => {
    if (targetDef.targetState && !targetDef.targetJourney) {
      targetDef.targetState = `${subJourneyState}/${targetDef.targetState}`;
    }
  });
};

// Expand out nested states
const expandNestedJourneys = (journeyMap, subjourneys, formData) => {
  Object.entries(journeyMap).forEach(([state, definition]) => {
    if (definition.nestedJourney && subjourneys[definition.nestedJourney]) {
      const subJourneyState = state;
      delete journeyMap[subJourneyState];
      const subjourney = subjourneys[definition.nestedJourney];

      // Expand out each of the nested states
      Object.entries(subjourney.nestedJourneyStates).forEach(
        ([nestedState, nestedDefinition]) => {
          // Copy to avoid mutating different versions of the expanded definition
          const expandedDefinition = JSON.parse(
            JSON.stringify(nestedDefinition),
          );

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
                if (definition.exitEvents[exitEvent]) {
                  Object.assign(eventDef, definition.exitEvents[exitEvent]);
                } else {
                  console.warn(
                    `Unhandled exit event from ${subJourneyState}:`,
                    exitEvent,
                  );
                  delete expandedDefinition.events[evt];
                }
              }
            },
          );

          journeyMap[`${subJourneyState}/${nestedState}`] = expandedDefinition;
        },
      );

      // Make a copy of the entry events to avoid mutating the original
      const entryEvents = JSON.parse(JSON.stringify(subjourney.entryEvents));
      // Update entry events on other states to expanded states
      Object.entries(entryEvents).forEach(([entryEvent, entryEventDef]) => {
        mapTargetStateToExpandedState(entryEventDef, subJourneyState, formData);

        Object.values(journeyMap).forEach((journeyDef) => {
          if (journeyDef.events?.[entryEvent]) {
            const target = resolveEventTargets(
              journeyDef.events[entryEvent],
              formData,
            ).find((t) => !t.journeyContext);
            if (
              target.targetState === subJourneyState &&
              !target.targetEntryEvent
            ) {
              journeyDef.events[entryEvent] = entryEventDef;
            }
          }

          // Resolve targets with a `targetEntryEvent` override
          Object.values(journeyDef.events ?? {}).forEach((eventDef) => {
            const target = resolveEventTargets(eventDef, formData).find(
              (t) => !t.journeyContext,
            );
            if (
              target.targetState === subJourneyState &&
              target.targetEntryEvent === entryEvent
            ) {
              Object.assign(target, entryEventDef);
              delete target.targetEntryEvent;
            }
          });
        });
      });
    }
  });
};

// Render the transitions into mermaid, while tracking the states traced from the initial states
// This allows us to skip
const renderTransitions = (journeyStates, formData, selectedJourney) => {
  // Initial states have no response or nested journey
  const initialStates = Object.keys(journeyStates).filter(
    (s) => !journeyStates[s].response && !journeyStates[s].nestedJourney,
  );

  const states = [...initialStates];
  const stateTransitions = [];

  for (let i = 0; i < states.length; i++) {
    const state = states[i];
    const definition = journeyStates[state];
    const events = definition.events || definition.exitEvents || {};

    const eventsByTarget = {};
    Object.entries(events).forEach(([eventName, def]) => {
      let resolvedEventTargets = resolveEventTargets(def, formData);

      for (const resolvedTarget of resolvedEventTargets) {
        // Special case for disabling TICF, to match the special case in the journey engine
        if (
          journeyStates[resolvedTarget.targetState]?.response?.lambda ===
            "call-ticf-cri" &&
          formData.getAll("disabledCri").includes("ticf")
        ) {
          resolvedEventTargets.push(
            ...resolveEventTargets(
              journeyStates[resolvedTarget.targetState].events.next,
              formData,
            ),
          );
          continue;
        }

        const {
          targetJourney,
          targetState,
          targetEntryEvent,
          exitEventToEmit,
          journeyContext,
        } = resolvedTarget;

        const target = exitEventToEmit
          ? `exit_${exitEventToEmit}`.toUpperCase()
          : targetJourney
            ? `${targetJourney}__${targetState}`
            : targetState;

        if (
          errorJourneys.includes(targetJourney) &&
          !formData.getAll("otherOption").includes("includeErrors")
        ) {
          return;
        }
        if (
          failureJourneys.includes(targetJourney) &&
          !formData.getAll("otherOption").includes("includeFailures")
        ) {
          return;
        }

        if (!states.includes(target)) {
          states.push(target);
        }

        eventsByTarget[target] = eventsByTarget[target] || [];
        const eventTransitionLabel = `${eventName}${targetEntryEvent ? `/${targetEntryEvent}` : ""}${journeyContext ? ` - journeyContext: ${journeyContext}` : ""}`;
        eventsByTarget[target].push(
          journeyContext
            ? `<span class="journeyCtxTransition">${eventTransitionLabel}</span>`
            : eventTransitionLabel,
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

    const isExpandingNested = formData.getAll("otherOption").includes("expandNestedJourneys");

    Object.entries(eventsByTarget).forEach(([target, eventNames]) => {
      // This currently doesn't work for
      // - exit events from a nested state (where the exit event and underlying event are different)
      // - entry events for a subjourney (where there are multiple entry events going to the same state)
      const transitionVisits = visits
          .filter((visit) =>
              // Transitions within the subjourney
              (visit.fromJourney === selectedJourney &&
              (isExpandingNested ? visit.from : visit.from.split("/")[0]) === state &&
              eventNames.map(ev => ev.split("/")[0]).includes(visit.event)) ||
              // Transitions into the subjourney
              (visit.fromJourney !== selectedJourney &&
                  visit.toJourney === selectedJourney &&
                  (isExpandingNested ? visit.to : visit.to.split("/")[0]) === target))
          .map((visit) => parseInt(visit.count))
          .reduce((a, b) => a + b, 0);

      stateTransitions.push(
        `    ${state}-->|${eventNames.join("\\n")}\n${transitionVisits}|${target}`,
      );
    });
  }

  return { transitionsMermaid: stateTransitions.join("\n"), states };
};

const renderClickHandler = (state, definition) => {
  if (definition.nestedJourney) {
    definition.response = {
      type: "nestedJourney",
      nestedJourney: definition.nestedJourney,
    };
  }
  // Click handler serializes the definition to Base64-encoded JSON to avoid escaping issues
  return `    click ${state} call onStateClick(${JSON.stringify(state)}, ${btoa(JSON.stringify(definition.response ?? {}))})`;
};

const renderState = (state, definition) => {
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
      const scopeInfo = definition.response.scope
        ? `\\n scope: ${definition.response.scope}`
        : "";
      return `    ${state}([${state}\\n${definition.response.criId}${contextInfo}${scopeInfo}]):::cri`;
    }
    case "journeyTransition": {
      const { targetJourney, targetState } = definition.response;
      return failureJourneys.includes(targetJourney) ||
        errorJourneys.includes(targetJourney)
        ? `    ${state}(${targetJourney}\\n${targetState}):::error_transition`
        : `    ${state}(${targetJourney}\\n${targetState}):::journey_transition`;
    }
    default:
      return `    ${state}:::other`;
  }
};

const renderStates = (journeyMapStates, states) => {
  const mermaids = states.flatMap((state) => {
    const definition = journeyMapStates[state];

    return [
      renderState(state, definition),
      renderClickHandler(state, definition),
    ];
  });

  return { statesMermaid: mermaids.join("\n") };
};

const resolveAllPossibleEventTargets = (eventDefinition) => [
  eventDefinition.targetState,
  ...Object.values(eventDefinition.checkIfDisabled || {}).flatMap(
    resolveAllPossibleEventTargets,
  ),
  ...Object.values(eventDefinition.checkFeatureFlag || {}).flatMap(
    resolveAllPossibleEventTargets,
  ),
];

const calcOrphanStates = (journeyMap) => {
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

const getMermaidGraph = (graphDirection, statesMermaid, transitionsMermaid) =>
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
  selectedJourney,
  journeyMap,
  nestedJourneys,
  formData = new FormData(),
) => {
  const isNestedJourney = selectedJourney in nestedJourneys;
  const direction = topDownJourneys.includes(selectedJourney) ? "TD" : "LR";

  // Copy to avoid mutating the input
  const journeyStates = JSON.parse(
    JSON.stringify(
      isNestedJourney
        ? getNestedJourneyStates(nestedJourneys[selectedJourney])
        : journeyMap.states,
    ),
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
    : renderTransitions(journeyStates, formData, selectedJourney);

  const { statesMermaid } = renderStates(journeyStates, states);

  return getMermaidGraph(direction, statesMermaid, transitionsMermaid);
};
