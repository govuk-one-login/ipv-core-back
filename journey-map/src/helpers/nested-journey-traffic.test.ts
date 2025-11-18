import { describe, it, beforeEach, afterEach, expect } from "vitest";
import { attachTransitionTrafficToNestedJourneys } from "./nested-journey-traffic.js";
import { TransitionEdge } from "./mermaid.js";
import { JourneyTransition } from "../data/data.js";

const TEST_JOURNEY_TRANSITION_TRAFFIC: JourneyTransition[] = [
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "POST_APP_DOC_CHECK_SUCCESS_PAGE",
    toJourney: "NEW_P2_IDENTITY",
    to: "ADDRESS_AND_FRAUD_J4/CRI_ADDRESS",
    event: "next",
    count: 7,
  },
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "POST_APP_DOC_CHECK_INTERNATIONAL_SUCCESS_PAGE",
    toJourney: "NEW_P2_IDENTITY",
    to: "ADDRESS_AND_FRAUD_J4/CRI_ADDRESS_ASK_INTERNATIONAL",
    toEntryEvent: "otherEntryEvent",
    event: "next",
    count: 8,
  },
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "ADDRESS_AND_FRAUD_J4/CRI_ADDRESS",
    toJourney: "NEW_P2_IDENTITY",
    to: "ADDRESS_AND_FRAUD_J4/CRI_FRAUD",
    event: "next",
    count: 10,
  },
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "ADDRESS_AND_FRAUD_J1/CRI_ADDRESS",
    toJourney: "NEW_P2_IDENTITY",
    to: "ADDRESS_AND_FRAUD_J4/CRI_FRAUD",
    event: "next",
    count: 10,
  },
  {
    fromJourney: "NEW_P1_IDENTITY",
    from: "ADDRESS_AND_FRAUD_J1/CRI_ADDRESS",
    toJourney: "NEW_P2_IDENTITY",
    to: "ADDRESS_AND_FRAUD_J4/CRI_FRAUD",
    event: "next",
    count: 10,
  },
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "ADDRESS_AND_FRAUD_J1/CRI_FRAUD",
    toJourney: "differentJourney",
    to: "someWhereElse",
    event: "next",
    count: 10,
  },
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "ADDRESS_AND_FRAUD_AFTER_PASSPORT/NESTED_JOURNEY/SOME_NODE_IN_NESTED_JOURNEY",
    toJourney: "NEW_P2_IDENTITY",
    to: "ADDRESS_AND_FRAUD_AFTER_PASSPORT/NEXT_NODE",
    event: "next",
    count: 10,
  },
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "ADDRESS_AND_FRAUD_AFTER_PASSPORT/NESTED_JOURNEY/MORE_NESTED_JOURNEY/SOME_NODE_IN_NESTED_JOURNEY",
    toJourney: "NEW_P2_IDENTITY",
    to: "ADDRESS_AND_FRAUD_AFTER_PASSPORT/NEXT_NODE",
    event: "next",
    count: 10,
  },
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "ADDRESS_AND_FRAUD_J1/CRI_FRAUD",
    toJourney: "NEW_P2_IDENTITY",
    to: "PROCESS_NEW_IDENTITY",
    event: "fail-with-no-ci",
    count: 3,
  },
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "ADDRESS_AND_FRAUD_J1/CRI_FRAUD",
    toJourney: "someOtherJourney",
    to: "FAILED_NODE",
    event: "failed-event",
    count: 5,
  },
];
const TEST_TRANSITION_EDGES: TransitionEdge[] = [
  {
    sourceState: "ENTRY_NEXT",
    targetState: "CRI_ADDRESS",
    transitionCount: 0,
    transitionEvents: [
      {
        eventName: "next",
      },
    ],
  },
  {
    sourceState: "ENTRY_OTHER",
    targetState: "CRI_ADDRESS_ASK_INTERNATIONAL",
    transitionCount: 0,
    transitionEvents: [
      {
        eventName: "otherEntryEvent",
      },
    ],
  },
  {
    sourceState: "CRI_ADDRESS",
    targetState: "CRI_FRAUD",
    transitionCount: 0,
    transitionEvents: [
      {
        eventName: "next",
      },
    ],
  },
  {
    sourceState: "CRI_FRAUD",
    targetState: "EXIT_NEXT",
    transitionCount: 0,
    transitionEvents: [
      {
        eventName: "next",
      },
    ],
  },
  {
    sourceState: "CRI_FRAUD",
    targetState: "EXIT_FRAUD-FAIL-WITH-NO-CI",
    transitionCount: 0,
    transitionEvents: [
      {
        eventName: "fail-with-no-ci",
      },
    ],
  },
  {
    sourceState: "NESTED_JOURNEY",
    targetState: "NEXT_NODE",
    transitionCount: 0,
    transitionEvents: [
      {
        eventName: "next",
      },
    ],
  },
  {
    sourceState: "CRI_FRAUD",
    targetState: "FAILED",
    transitionCount: 0,
    transitionEvents: [
      {
        eventName: "failed-event",
      },
    ],
  },
  {
    sourceState: "NODE_WITH_NO_TRANSITION",
    targetState: "SOME_NODE",
    transitionCount: 0,
    transitionEvents: [
      {
        eventName: "next",
      },
    ],
  },
];

interface MockWindow {
  location: { search: string };
}

beforeEach(() => {
  Object.defineProperty(globalThis, "window", {
    value: { location: { search: "" } } as MockWindow,
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  Reflect.deleteProperty(globalThis, "window");
});

describe("nestedJourneysTraffic", () => {
  it("should attach journey traffic", () => {
    // Arrange
    (
      globalThis as typeof globalThis & { window: MockWindow }
    ).window.location.search =
      "?journeyType=NEW_P2_IDENTITY&nestedJourneyType=ADDRESS_AND_FRAUD";

    // Act
    attachTransitionTrafficToNestedJourneys(
      TEST_JOURNEY_TRANSITION_TRAFFIC,
      TEST_TRANSITION_EDGES,
    );

    // Assert - entry nodes
    const defaultEntryEdge = TEST_TRANSITION_EDGES.find(
      (edge) =>
        edge.sourceState === "ENTRY_NEXT" && edge.targetState === "CRI_ADDRESS",
    );
    expect(defaultEntryEdge?.transitionCount).toEqual(7);

    const otherEntryEdge = TEST_TRANSITION_EDGES.find(
      (edge) =>
        edge.sourceState === "ENTRY_OTHER" &&
        edge.targetState === "CRI_ADDRESS_ASK_INTERNATIONAL",
    );
    expect(otherEntryEdge?.transitionCount).toEqual(8);

    // Assert - mid nodes
    const midEdge = TEST_TRANSITION_EDGES.find(
      (edge) =>
        edge.sourceState === "CRI_ADDRESS" && edge.targetState === "CRI_FRAUD",
    );
    expect(midEdge?.transitionCount).toEqual(20);

    // Assert - exit nodes
    const exitEdge = TEST_TRANSITION_EDGES.find(
      (edge) =>
        edge.sourceState === "CRI_FRAUD" && edge.targetState === "EXIT_NEXT",
    );
    expect(exitEdge?.transitionCount).toEqual(10);

    // Assert - exit nodes - different exit than above
    const differentExitEdge = TEST_TRANSITION_EDGES.find(
      (edge) =>
        edge.sourceState === "CRI_FRAUD" &&
        edge.targetState === "EXIT_FRAUD-FAIL-WITH-NO-CI",
    );
    expect(differentExitEdge?.transitionCount).toEqual(3);

    // Assert - from nested journey node
    const moreNestedToCurrentNested = TEST_TRANSITION_EDGES.find(
      (edge) =>
        edge.sourceState === "NESTED_JOURNEY" &&
        edge.targetState === "NEXT_NODE",
    );
    expect(moreNestedToCurrentNested?.transitionCount).toEqual(20);

    // Assert - to error nodes
    const toFailedNodeEdge = TEST_TRANSITION_EDGES.find(
      (edge) =>
        edge.sourceState === "CRI_FRAUD" && edge.targetState === "FAILED",
    );
    expect(toFailedNodeEdge?.transitionCount).toEqual(5);

    // Assert - no transitions
    const noTransitionEdge = TEST_TRANSITION_EDGES.find(
      (edge) =>
        edge.sourceState === "NODE_WITH_NO_TRANSITION" &&
        edge.targetState === "SOME_NODE",
    );
    expect(noTransitionEdge?.transitionCount).toEqual(0);
  });
});
