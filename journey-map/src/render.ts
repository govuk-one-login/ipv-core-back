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
import { getJourneyTransitionsData, JourneyTransition } from "./data/data.js";

interface RenderableMap {
  transitions: TransitionEdge[];
  states: StateNode[];
}

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
  const transitionEdges: TransitionEdge[] = [];

  const journeyTransitionsTraffic = getJourneyTransitionsData();
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
      for (const transition of journeyTransitionsTraffic) {
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

      transitionEdges.push({
        sourceState,
        targetState,
        transitionCount: count,
        transitionEvents,
      });
    }
  }

  handleEntryNestedJourneyTraffic(journeyTransitionsTraffic, transitionEdges);
  handleNestedJourneyTraffic(journeyTransitionsTraffic, transitionEdges);
  handleOutFromNestedJourneysInNestedJourneys(
    journeyTransitionsTraffic,
    transitionEdges,
  );

  return {
    transitions: transitionEdges,
    states: states.map((name) => ({ name, definition: journeyStates[name] })),
  };
};

const getBeforeLastSegment = (str: string): string => {
  const parts = str.split("/");
  return parts.length >= 2 ? parts[parts.length - 2] : str;
};

const handleOutFromNestedJourneysInNestedJourneys = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
) => {
  const params = new URLSearchParams(window.location.search);
  const journeyTypeUrlParam = params.get("journeyType");
  const nestedJourneyTypeUrlParam = params.get("nestedJourneyType");
  if (!nestedJourneyTypeUrlParam) {
    return;
  }

  for (const edge of transitionsEdges) {
    const prefix = `${nestedJourneyTypeUrlParam}/${edge.sourceState}/`;
    const filteredTransitions = journeyTransitionsTraffic
      .filter((transition) => transition.fromJourney === journeyTypeUrlParam)
      .filter((transition) => transition.from.startsWith(prefix))
      .filter((transition) => !transition.to.startsWith(prefix));

    for (const transition of filteredTransitions) {
      if (edge.transitionCount) {
        edge.transitionCount += transition.count;
      } else {
        edge.transitionCount = transition.count;
      }
    }
  }
};

const handleEntryNestedJourneyTraffic = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
) => {
  const params = new URLSearchParams(window.location.search);
  const journeyTypeUrlParam = params.get("journeyType");
  const nestedJourneyTypeUrlParam = params.get("nestedJourneyType");
  if (!nestedJourneyTypeUrlParam) {
    return;
  }
  for (const journeyTransition of journeyTransitionsTraffic) {
    if (journeyTransition.fromJourney !== journeyTypeUrlParam) {
      continue;
    }
    if (
      !getBeforeLastSegment(journeyTransition.to).startsWith(
        nestedJourneyTypeUrlParam,
      )
    ) {
      continue;
    }
    const toState = journeyTransition.to.substring(
      journeyTransition.to.lastIndexOf("/") + 1,
    );
    const edges = transitionsEdges.filter((edge) =>
      edge.sourceState.startsWith("ENTRY_"),
    );
    const edge = edges.find((edge) => edge.targetState === toState);
    if (!edge) {
      continue;
    }
    if (edge.transitionCount) {
      edge.transitionCount += journeyTransition.count;
    } else {
      edge.transitionCount = journeyTransition.count;
    }
  }
};

const handleNestedJourneyTraffic = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
) => {
  const params = new URLSearchParams(window.location.search);
  const journeyTypeUrlParam = params.get("journeyType");
  const nestedJourneyTypeUrlParam = params.get("nestedJourneyType");
  if (!nestedJourneyTypeUrlParam) {
    return;
  }
  for (const journeyTransition of journeyTransitionsTraffic) {
    if (journeyTransition.fromJourney !== journeyTypeUrlParam) {
      continue;
    }
    const nestedJourney = getBeforeLastSegment(journeyTransition.from);
    if (!nestedJourney.startsWith(nestedJourneyTypeUrlParam)) {
      continue;
    }
    const fromState = journeyTransition.from.substring(
      journeyTransition.from.lastIndexOf("/") + 1,
    );
    const event = journeyTransition.event;
    const edges = transitionsEdges.filter(
      (edge) => edge.sourceState === fromState,
    );
    const edge = edges.find((edge) =>
      edge.transitionEvents.find((te) => te.eventName === event),
    );
    if (!edge) {
      continue;
    }
    if (edge.transitionCount) {
      edge.transitionCount += journeyTransition.count;
    } else {
      edge.transitionCount = journeyTransition.count;
    }
  }
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

  const maxCount = Math.max(
    0,
    ...transitions.map((t) => t.transitionCount ?? 0),
  );
  const transitionStrings = transitions.flatMap((t, i) => {
    const colour = t.transitionCount
      ? `#FF8888${alphaFromCount(t.transitionCount, maxCount)}`
      : "#E5E4E2";
    const strokeWidth = getStrokeWidth(t.transitionCount ?? 0, maxCount);
    return [
      renderTransition(t),
      `linkStyle ${i} stroke:${colour}, stroke-width:${strokeWidth}px;`,
    ];
  });

  return `${getMermaidHeader(direction)}
    ${states.map(renderState).join("\n")}
    ${states.map(renderClickHandler).join("\n")}
    ${transitionStrings.join("\n")}
  `;
};

const getStrokeWidth = (count: number, maxCount: number): number => {
  if (maxCount <= 0) return 2;
  const minWidth = 2;
  const maxWidth = 6;
  const ratio = Math.min(1, Math.max(0, count / maxCount));
  return minWidth + (maxWidth - minWidth) * ratio;
};

function alphaFromCount(count: number, maxCount: number) {
  if (maxCount === 0) return "00";
  const ratio = count / maxCount;

  const exponent = 0.1;
  const powerScaled = Math.pow(ratio, exponent);

  const minAlpha = 0.1;
  const scaled = minAlpha + (1 - minAlpha) * powerScaled;

  const alpha = Math.round(scaled * 255);
  return alpha.toString(16).padStart(2, "0");
}
