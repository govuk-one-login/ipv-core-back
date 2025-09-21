import { TransitionEdge } from "./mermaid.js";
import { JourneyTransition } from "../data/data.js";

export const attachTransitionTrafficToNestedJourneys = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
) => {
  const params = new URLSearchParams(window.location.search);
  const journeyTypeUrlParam = params.get("journeyType");
  const nestedJourneyTypeUrlParam = params.get("nestedJourneyType");
  if (!nestedJourneyTypeUrlParam || !journeyTypeUrlParam) {
    return;
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

const handleOutFromNestedJourneysInNestedJourneys = (
  journeyTransitionsTraffic: JourneyTransition[],
  transitionsEdges: TransitionEdge[],
  journeyTypeUrlParam: string,
  nestedJourneyTypeUrlParam: string,
) => {
  for (const edge of transitionsEdges) {
    const prefix = `${nestedJourneyTypeUrlParam}/${edge.sourceState}/`;
    const count = journeyTransitionsTraffic
      .filter((transition) => transition.fromJourney === journeyTypeUrlParam)
      .filter((transition) => transition.from.startsWith(prefix))
      .filter((transition) => !transition.to.startsWith(prefix))
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
    if (!edge.sourceState.startsWith("ENTRY_")) {
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
        edge.transitionEvents.find((te) => te.eventName === transition.event),
      )
      .reduce((sum, transition) => sum + (transition.count ?? 0), 0);

    if (count > 0) {
      edge.transitionCount = count;
    }
  }
};
