import { getAsFullJourneyMap } from "./helpers/uplift-nested.js";
import { resolveVisibleEventTargets } from "./helpers/event-resolver.js";
import { expandNestedJourneys } from "./helpers/expand-nested.js";
import { expandParents } from "./helpers/expand-parents.js";
import { RenderOptions } from "./helpers/options.js";
import { findOrphanStates } from "./helpers/orphans.js";
import { JourneyMap, JourneyState, NestedJourneyMap } from "./types.js";
import { deepCloneJson } from "./helpers/deep-clone.js";
import { addJourneyTransitions } from "./helpers/add-journey-transitions.js";
import {
  getMermaidHeader,
  renderClickHandler,
  renderState,
  renderTransition,
  StateNode,
  TransitionEdge,
  TransitionEvent,
} from "./helpers/mermaid.js";
import {
  ERROR_JOURNEYS,
  FAILURE_JOURNEYS,
  TOP_DOWN_JOURNEYS,
} from "./constants.js";
import { contractNestedJourneys } from "./helpers/contract-nested.js";

interface RenderableMap {
  transitions: TransitionEdge[];
  states: StateNode[];
}

interface JourneyTransition {
  fromJourney: string;
  from: string;
  toJourney: string;
  to: string;
  count: number;
}

const getJourneyTransitions = async (): Promise<JourneyTransition[]> => {
  const query = new URLSearchParams({
    minutes: "30",
    limit: "500",
    // ipvSessionId: "test-session-1",
  });

  const response = await fetch(
    `https://api-dev.01.dev.identity.account.gov.uk/journey-transitions?${query.toString()}`,
  );

  if (!response.ok) {
    throw new Error(`Failed to fetch journey transitions: ${response.status}`);
  }

  return response.json();
};

// Trace transitions (edges) and states (nodes) traced from the initial states
// This allows us to skip unreachable states
const getVisibleEdgesAndNodes = async (
  journeyStates: Record<string, JourneyState>,
  options: RenderOptions,
): Promise<RenderableMap> => {
  // Initial states have no response or nested journey
  const initialStates = Object.keys(journeyStates).filter(
    (s) => !journeyStates[s].response && !journeyStates[s].nestedJourney,
  );

  const states = [...initialStates];
  const transitions: TransitionEdge[] = [];

  const journeyTransitions: JourneyTransition[] = await getJourneyTransitions();
  for (const sourceState of states) {
    const definition = journeyStates[sourceState];
    const events = definition.events || definition.exitEvents || {};

    const eventsByTarget: Record<string, TransitionEvent[]> = {};
    Object.entries(events).forEach(([eventName, def]) => {
      const resolvedEventTargets = resolveVisibleEventTargets(def, options);

      for (const resolvedTarget of resolvedEventTargets) {
        const { targetState, targetEntryEvent, journeyContext, mitigation } =
          resolvedTarget;

        // Check the target state resolves properly and is not hidden
        const resolvedTargetState = journeyStates[targetState];
        if (!resolvedTargetState) {
          throw new Error(
            `Failed to resolve state ${targetState} from ${sourceState}`,
          );
        } else if (
          ERROR_JOURNEYS.includes(
            resolvedTargetState.response?.targetJourney as string,
          ) &&
          !options.includeErrors
        ) {
          continue;
        } else if (
          FAILURE_JOURNEYS.includes(
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
        eventsByTarget[targetState].push({
          eventName,
          targetEntryEvent,
          journeyContext,
          mitigation,
        });
      }
    });

    Object.entries(eventsByTarget).forEach(
      ([targetState, transitionEvents]) => {
        transitions.push({
          sourceState,
          targetState,
          transitionCount:
            journeyTransitions.find(
              (transition) =>
                transition.fromJourney === definition.parent &&
                transition.from === sourceState &&
                transition.toJourney === definition.parent &&
                transition.to === targetState,
            )?.count ?? 0,
          transitionEvents,
        });
      },
    );
  }

  return {
    transitions,
    states: states.map((name) => ({ name, definition: journeyStates[name] })),
  };
};

export const render = async (
  selectedJourney: string,
  journeyMap: JourneyMap,
  nestedJourneys: Record<string, NestedJourneyMap>,
  options: RenderOptions,
): Promise<string> => {
  const isNestedJourney = selectedJourney in nestedJourneys;
  const direction = TOP_DOWN_JOURNEYS.includes(selectedJourney) ? "TD" : "LR";

  // Copy to avoid mutating the input
  const journeyStates = deepCloneJson(
    isNestedJourney
      ? getAsFullJourneyMap(nestedJourneys[selectedJourney])
      : journeyMap,
  ).states;

  if (options.expandNestedJourneys) {
    expandNestedJourneys(journeyStates, nestedJourneys);
  } else {
    contractNestedJourneys(journeyStates);
  }

  expandParents(journeyStates, journeyMap.states);
  addJourneyTransitions(journeyStates);

  const { transitions, states } = options.onlyOrphanStates
    ? { transitions: [], states: findOrphanStates(journeyStates) }
    : await getVisibleEdgesAndNodes(journeyStates, options);

  return `${getMermaidHeader(direction)}
    ${states.map(renderState).join("\n")}
    ${states.map(renderClickHandler).join("\n")}
    ${transitions.map(renderTransition).join("\n")}
  `;
};
