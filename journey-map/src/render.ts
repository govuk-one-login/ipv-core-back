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
import { getJourneyTransitionsData } from "./data/data.js";
import { attachTransitionTrafficToNestedJourneys } from "./helpers/nested-journey-traffic.js";
import { getTransitionCountFromSubJourneyStateToTargetState } from "./helpers/sub-journey-traffic.js";

interface RenderableMap {
  transitions: TransitionEdge[];
  states: StateNode[];
}

const DEFAULT_EDGE_COLOUR = "#ADADAC";
const HIGHLIGHTED_JOURNEY_EDGE_COLOUR = "#FF8888";

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
  console.log(journeyTransitionsTraffic);
  console.log(journeyStates);
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

    console.log(eventsByTarget);

    for (const [targetState, transitionEvents] of Object.entries(
      eventsByTarget,
    )) {
      const count = getTransitionCountFromSubJourneyStateToTargetState(
        journeyStates,
        journeyMapName,
        journeyMaps,
        journeyTransitionsTraffic,
        sourceState,
        targetState,
        Object.keys(eventsByTarget),
      );

      transitionEdges.push({
        sourceState,
        targetState,
        transitionCount: count,
        transitionEvents,
      });
    }
  }

  attachTransitionTrafficToNestedJourneys(
    journeyTransitionsTraffic,
    transitionEdges,
  );

  return {
    transitions: transitionEdges,
    states: states.map((name) => ({ name, definition: journeyStates[name] })),
  };
};

export const render = async (
  selectedJourney: string,
  journeyMap: JourneyMap,
  nestedJourneys: Record<string, NestedJourneyMap>,
  options: RenderOptions,
  journeyMaps: Record<string, JourneyMap>,
): Promise<{ mermaidString: string; edgeIds: string[] }> => {
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
      ? `${HIGHLIGHTED_JOURNEY_EDGE_COLOUR}${alphaFromCount(t.transitionCount, maxCount)}`
      : DEFAULT_EDGE_COLOUR;
    const strokeWidth = getStrokeWidth(t.transitionCount ?? 0, maxCount);
    return [
      renderTransition(t),
      `linkStyle ${i} stroke:${colour}, stroke-width:${strokeWidth}px;`,
    ];
  });

  const edgeIds = transitionStrings
    .filter((_, idx) => (idx + 1) % 2 !== 0)
    .map((transitionString) => {
      const trimmed = transitionString.trimStart();
      return trimmed.slice(trimmed.indexOf(" ") + 1, trimmed.indexOf("@"));
    });

  return {
    mermaidString: `${getMermaidHeader(direction)}
    ${states.map(renderState).join("\n")}
    ${states.map(renderClickHandler).join("\n")}
    ${transitionStrings.join("\n")}
  `,
    edgeIds,
  };
};

const getStrokeWidth = (count: number, maxCount: number): number => {
  if (maxCount <= 0) return 2;
  const minWidth = 2;
  const maxWidth = 8;
  const ratio = Math.min(1, Math.max(0, count / maxCount));
  return minWidth + (maxWidth - minWidth) * ratio;
};

function alphaFromCount(count: number, maxCount: number) {
  if (maxCount === 0) return "00";
  const ratio = count / maxCount;

  const exponent = 0.8;
  const powerScaled = Math.pow(ratio, exponent);

  const minAlpha = 0.8;
  const scaled = minAlpha + (1 - minAlpha) * powerScaled;

  const alpha = Math.round(scaled * 255);
  return alpha.toString(16).padStart(2, "0");
}
