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
  const query = new URLSearchParams({});
  const response = await fetch(`/journey-transitions?${query}`);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch journey transitions from journey map server: ${response.statusText}`,
    );
  }
  return response.json();
};

// Trace transitions (edges) and states (nodes) traced from the initial states
// This allows us to skip unreachable states
const getVisibleEdgesAndNodes = async (
  journeyStates: Record<string, JourneyState>,
  options: RenderOptions,
  journeyMapName: string,
  journeyMaps: Record<string, JourneyMap>,
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

    for (const [targetState, transitionEvents] of Object.entries(
      eventsByTarget,
    )) {
      const sourceStateDefinition = journeyStates[sourceState];
      const targetStateDefinition = journeyStates[targetState];
      const sourceIsNestedJourney =
        sourceStateDefinition.response?.type === "nestedJourney";
      const targetIsNestedJourney =
        targetStateDefinition.response?.type === "nestedJourney";

      let count = 0;
      for (const transition of journeyTransitions) {
        // Source condition
        if (sourceIsNestedJourney) {
          if (
            !(
              transition.fromJourney === journeyMapName &&
              transition.from.startsWith(sourceState)
            )
          ) {
            continue;
          }
        } else if (!sourceStateDefinition.response) {
          // Entry state, so the source does not matter
        } else {
          if (
            !(
              transition.fromJourney === journeyMapName &&
              transition.from === sourceState
            )
          ) {
            continue;
          }
        }

        // Target condition
        if (targetIsNestedJourney) {
          if (
            !(
              transition.toJourney === journeyMapName &&
              transition.to.startsWith(targetState)
            )
          ) {
            continue;
          }
        } else if (targetState.includes("__")) {
          const [targetJourney, entryState] = targetState.split("__", 2);
          const actualState =
            journeyMaps[targetJourney].states[entryState].events?.next
              .targetState;
          if (
            !(
              transition.toJourney === targetJourney &&
              transition.to === actualState
            )
          ) {
            continue;
          }
        } else {
          if (
            !(
              transition.toJourney === journeyMapName &&
              transition.to === targetState
            )
          ) {
            continue;
          }
        }
        count += transition.count;
      }

      transitions.push({
        sourceState,
        targetState,
        transitionCount: count,
        transitionEvents,
      });
    }
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
  journeyMaps: Record<string, JourneyMap>,
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
    : await getVisibleEdgesAndNodes(
        journeyStates,
        options,
        selectedJourney,
        journeyMaps,
      );

  const maxCount = Math.max(...transitions.map((t) => t.transitionCount || 0));

  let linkIndex = 0;
  const transitionStrings: string[] = [];
  for (const t of transitions) {
    let colour = "#E5E4E2";

    if (t.transitionCount) {
      colour = "#000000" + alphaFromCount(t.transitionCount, maxCount);
    }

    const edge = renderTransition(t);
    transitionStrings.push(edge);
    transitionStrings.push(
      `linkStyle ${linkIndex} stroke:${colour}, stroke-width:2px;`,
    );
    linkIndex++;
  }

  return `${getMermaidHeader(direction)}
    ${states.map(renderState).join("\n")}
    ${states.map(renderClickHandler).join("\n")}
    ${transitionStrings.join("\n")}
  `;
};

function alphaFromCount(count: number, maxCount: number) {
  if (maxCount === 0) return "00";
  const ratio = count / maxCount;
  const logScaled = Math.log10(1 + 9 * ratio);
  const alpha = Math.round(logScaled * 255);
  return alpha.toString(16).padStart(2, "0");
}
