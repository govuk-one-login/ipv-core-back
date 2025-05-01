import { getAsFullJourneyMap } from "./helpers/uplift-nested.js";
import { resolveVisibleEventTargets } from "./helpers/event-resolver.js";
import { expandNestedJourneys } from "./helpers/expand-nested.js";
import { expandParents } from "./helpers/expand-parents.js";
import { RenderOptions } from "./helpers/options.js";
import { findOrphanStates } from "./helpers/orphans.js";
import { JourneyMap, JourneyState, NestedJourneyMap } from "./types.js";
import { deepCloneJson } from "./helpers/deep-clone.js";
import { addJourneyTransitions } from "./helpers/add-journey-transitions.js";

const topDownJourneys = ["INITIAL_JOURNEY_SELECTION"];
const errorJourneys = ["TECHNICAL_ERROR"];
const failureJourneys = ["INELIGIBLE", "FAILED"];

const JOURNEY_CONTEXT_TRANSITION_CLASSNAME = "journeyCtxTransition";
const MITIGATIONS_TRANSITION_CLASSNAME = "mitigationTransition";

interface TransitionsOutput {
  transitionsMermaid: string;
  states: string[];
}

// Render the transitions into mermaid, while tracking the states traced from the initial states
// This allows us to skip unreachable states
const renderTransitions = (
  journeyStates: Record<string, JourneyState>,
  options: RenderOptions,
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
      const resolvedEventTargets = resolveVisibleEventTargets(def, options);

      for (const resolvedTarget of resolvedEventTargets) {
        const { targetState, targetEntryEvent, journeyContext, mitigation } =
          resolvedTarget;

        // Check the target state resolves properly and is not hidden
        const resolvedTargetState = journeyStates[targetState];
        if (!resolvedTargetState) {
          throw new Error(
            `Failed to resolve state ${targetState} from ${state}`,
          );
        } else if (
          errorJourneys.includes(
            resolvedTargetState.response?.targetJourney as string,
          ) &&
          !options.includeErrors
        ) {
          continue;
        } else if (
          failureJourneys.includes(
            resolvedTargetState.response?.targetJourney as string,
          ) &&
          !options.includeFailures
        ) {
          continue;
        }

        if (!states.includes(targetState)) {
          states.push(targetState);
        }

        eventsByTarget[targetState] = eventsByTarget[targetState] || [];
        eventsByTarget[targetState].push(
          createTransitionLabel({
            eventName,
            targetEntryEvent,
            journeyContext,
            mitigation,
          }),
        );
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
  options: RenderOptions,
): string => {
  const isNestedJourney = selectedJourney in nestedJourneys;
  const direction = topDownJourneys.includes(selectedJourney) ? "TD" : "LR";

  // Copy to avoid mutating the input
  const journeyStates = deepCloneJson(
    isNestedJourney
      ? getAsFullJourneyMap(nestedJourneys[selectedJourney])
      : journeyMap,
  ).states;

  if (!isNestedJourney && options.expandNestedJourneys) {
    expandNestedJourneys(journeyStates, nestedJourneys);
  }

  expandParents(journeyStates, journeyMap.states);
  addJourneyTransitions(journeyStates);

  const { transitionsMermaid, states } = options.onlyOrphanStates
    ? { transitionsMermaid: "", states: findOrphanStates(journeyStates) }
    : renderTransitions(journeyStates, options);

  const statesMermaid = renderStates(journeyStates, states);

  return getMermaidGraph(direction, statesMermaid, transitionsMermaid);
};
