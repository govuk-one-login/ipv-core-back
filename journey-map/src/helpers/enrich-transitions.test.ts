import { JourneyTransition } from "../data/data.js";
import { JourneyMap, NestedJourneyMap } from "../types.js";
import { describe, it, expect } from "vitest";
import { enrichJourneyTransitionData } from "./enrich-transitions.js";
import { deepCloneJson } from "./deep-clone.js";

const TEST_TRANSITION_JOURNEY_TO_NESTED: JourneyTransition[] = [
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "BASE_JOURNEY_STATE",
    toJourney: "NEW_P2_IDENTITY",
    to: "NESTED_JOURNEY/NESTED_ENTRY_STATE",
    event: "next",
    count: 8,
  },
];

const TEST_TRANSITION_NESTED_TO_NESTED: JourneyTransition[] = [
  {
    fromJourney: "NEW_P2_IDENTITY",
    from: "NESTED_JOURNEY/NESTED_MID_STATE",
    toJourney: "NEW_P2_IDENTITY",
    to: "NESTED_JOURNEY/DOUBLE_NESTED_JOURNEY/DOUBLE_NESTED_ENTRY_STATE",
    event: "next",
    count: 9,
  },
];

describe("traffic-enrichment", () => {
  it("should add nestedEntryEvent to nested entry traffic", () => {
    // Arrange
    const transition = deepCloneJson(TEST_TRANSITION_JOURNEY_TO_NESTED);

    // Act
    enrichJourneyTransitionData(
      transition,
      TEST_JOURNEY_MAPS,
      TEST_NESTED_JOURNEY_MAPS,
    );

    // Assert
    expect(transition[0].toEntryEvent).toEqual("nestedEntryEvent");
  });

  it("should add nestedEntryEvent to double nested entry traffic", () => {
    // Arrange
    const transition = deepCloneJson(TEST_TRANSITION_NESTED_TO_NESTED);

    // Act
    enrichJourneyTransitionData(
      transition,
      TEST_JOURNEY_MAPS,
      TEST_NESTED_JOURNEY_MAPS,
    );

    // Assert
    expect(transition[0].toEntryEvent).toEqual("doubleNestedEntryEvent");
  });
});

const NEW_P2_IDENTITY_JOURNEY_MAP: JourneyMap = {
  name: "New P2 Identity",
  description:
    "The routes a user can take to prove their identity to at least a medium confidence level (P2).",
  states: {
    BASE_JOURNEY_STATE: {
      response: {
        type: "page",
        pageId: "page-dcmaw-success",
      },
      events: {
        next: {
          targetState: "NESTED_JOURNEY_STATE",
          targetEntryEvent: "nestedEntryEvent",
        },
      },
    },
    NESTED_JOURNEY_STATE: {
      nestedJourney: "NESTED_JOURNEY",
    },
  },
};
const TEST_JOURNEY_MAPS: Record<string, JourneyMap> = {
  NEW_P2_IDENTITY: NEW_P2_IDENTITY_JOURNEY_MAP,
};

const NESTED_JOURNEY_MAP: NestedJourneyMap = {
  name: "Test nested journey",
  description: "The combined journey for Address and Fraud CRIs.",
  entryEvents: {
    nestedEntryEvent: {
      targetState: "NESTED_ENTRY_STATE",
    },
  },
  nestedJourneyStates: {
    NESTED_ENTRY_STATE: {
      response: {
        type: "cri",
        criId: "address",
      },
      parent: "CRI_STATE",
      events: {
        next: {
          targetState: "CRI_FRAUD",
        },
        "fail-with-ci": {
          targetJourney: "FAILED",
          targetState: "FAILED",
        },
      },
    },
    NESTED_MID_STATE: {
      response: {
        type: "page",
        pageId: "page-dcmaw-success",
      },
      events: {
        next: {
          targetState: "DOUBLE_NESTED_JOURNEY_STATE",
          targetEntryEvent: "doubleNestedEntryEvent",
        },
      },
    },
    DOUBLE_NESTED_JOURNEY_STATE: {
      nestedJourney: "DOUBLE_NESTED_JOURNEY",
    },
  },
};
const DOUBLE_NESTED_JOURNEY_MAP: NestedJourneyMap = {
  name: "Test double nested journey",
  description: "The combined journey for Address and Fraud CRIs.",
  entryEvents: {
    doubleNestedEntryEvent: {
      targetState: "DOUBLE_NESTED_ENTRY_STATE",
    },
  },
  nestedJourneyStates: {
    DOUBLE_NESTED_ENTRY_STATE: {
      response: {
        type: "cri",
        criId: "address",
      },
      parent: "CRI_STATE",
      events: {
        next: {
          targetState: "CRI_FRAUD",
        },
        "fail-with-ci": {
          targetJourney: "FAILED",
          targetState: "FAILED",
        },
      },
    },
  },
};
const TEST_NESTED_JOURNEY_MAPS: Record<string, NestedJourneyMap> = {
  NESTED_JOURNEY: NESTED_JOURNEY_MAP,
  DOUBLE_NESTED_JOURNEY_MAP: DOUBLE_NESTED_JOURNEY_MAP,
};
