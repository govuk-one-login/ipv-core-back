import { TransitionEdge } from "./mermaid.js";
import { JourneyTransition } from "../data/data.js";
import { ENTRY_STATE_PREFIX } from "../constants.js";

export const attachTransitionTrafficToNestedJourneys = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
) => {
  const params = new URLSearchParams(window.location.search);
  const journeyTypeUrlParam = params.get("journeyType");
  let nestedJourneyTypeUrlParam = params.get("nestedJourneyType");
  if (!nestedJourneyTypeUrlParam || !journeyTypeUrlParam) {
    return;
  }

  // Nested journey is called KBVs but state transitions events 'from' starting with KBV_
  if (nestedJourneyTypeUrlParam === "KBVS") {
    nestedJourneyTypeUrlParam = "KBV";
  }

  handleOutFromNestedJourneysInNestedJourneys(
    journeyTransitionsTraffic,
    transitionsEdges,
    journeyTypeUrlParam,
    nestedJourneyTypeUrlParam,
  );
  handleNestedJourneyMidOutTraffic(
    journeyTransitionsTraffic,
    transitionsEdges,
    journeyTypeUrlParam,
    nestedJourneyTypeUrlParam,
  );
  handleEntryNestedJourneyTraffic(
    journeyTransitionsTraffic,
    transitionsEdges,
    journeyTypeUrlParam,
    nestedJourneyTypeUrlParam,
  );
};

const getBeforeLastSegment = (str: string): string => {
  const parts = str.split("/");
  return parts.length >= 2 ? parts[parts.length - 2] : str;
};

const getBeforeFirstSlash = (str: string): string => {
  return str.split("/")[0];
};

const createPrefix = (
  from: string,
  nestedJourneyUrlParam: string,
  edge: TransitionEdge,
): string => {
  const firstPrefix = getBeforeFirstSlash(from);
  if (!firstPrefix.startsWith(nestedJourneyUrlParam)) {
    return "invalid-nested-journey";
  }
  return `${firstPrefix}/${edge.sourceState}/`;
};

const handleOutFromNestedJourneysInNestedJourneys = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
  journeyTypeUrlParam: string,
  nestedJourneyTypeUrlParam: string,
) => {
  for (const edge of transitionsEdges) {
    const count = journeyTransitionsTraffic
      .filter((transition) => transition.fromJourney === journeyTypeUrlParam)
      .filter((transition) =>
        transition.from.startsWith(
          createPrefix(transition.from, nestedJourneyTypeUrlParam, edge),
        ),
      )
      .filter(
        (transition) =>
          !transition.to.startsWith(
            createPrefix(transition.from, nestedJourneyTypeUrlParam, edge),
          ),
      )
      .filter((transition) =>
        edge.transitionEvents.find((te) => te.eventName === transition.event),
      )
      .reduce((sum, transition) => sum + (transition.count ?? 0), 0);

    if (count > 0) {
      edge.transitionCount = count;
    }
  }
};

const handleNestedJourneyMidOutTraffic = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
  journeyTypeUrlParam: string,
  nestedJourneyTypeUrlParam: string,
) => {
  for (const edge of transitionsEdges) {
    const count = journeyTransitionsTraffic
      .filter((transition) => transition.fromJourney === journeyTypeUrlParam)
      .filter((transition) =>
        getBeforeLastSegment(transition.from).startsWith(
          nestedJourneyTypeUrlParam,
        ),
      )
      .map((transition) => ({
        ...transition,
        from: transition.from.substring(transition.from.lastIndexOf("/") + 1),
      }))
      .filter((transition) => edge.sourceState === transition.from)
      .filter((transition) =>
        edge.transitionEvents.find((te) => te.eventName === transition.event),
      )
      .reduce((sum, transition) => sum + (transition.count ?? 0), 0);

    if (count > 0) {
      edge.transitionCount = count;
    }
  }
};

const handleEntryNestedJourneyTraffic = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
  journeyTypeUrlParam: string,
  nestedJourneyTypeUrlParam: string,
) => {
  for (const edge of transitionsEdges) {
    if (!edge.sourceState.startsWith(ENTRY_STATE_PREFIX)) {
      continue;
    }

    const count = journeyTransitionsTraffic
      .filter((transition) => transition.fromJourney === journeyTypeUrlParam)
      .filter((transition) =>
        getBeforeLastSegment(transition.to).startsWith(
          nestedJourneyTypeUrlParam,
        ),
      )
      .map((transition) => ({
        ...transition,
        toState: transition.to.substring(transition.to.lastIndexOf("/") + 1),
      }))
      .filter((transition) => transition.toState === edge.targetState)
      .filter((transition) =>
        edge.transitionEvents.find(
          (te) =>
            te.eventName === (transition.toEntryEvent || transition.event),
        ),
      )
      .reduce((sum, transition) => sum + (transition.count ?? 0), 0);

    if (count > 0) {
      edge.transitionCount = count;
    }
  }
};
