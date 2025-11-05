import { vi, describe, test, expect } from "vitest";
import { getTransitionCountFromSubJourneyStateToTargetState } from "./sub-journey-traffic.js";
import { JourneyState } from "../types.js";
import { JourneyTransition } from "../data/data.js";

vi.mock("../constants.js", () => ({
  FIRST_JOURNEYS: ["FIRST_SUB_JOURNEY"],
}));

describe("getTransitionCountFromSubJourneyStateToTargetState", () => {
  test.each([
    {
      testCase:
        "the sourceState is a basic state and the targetState is a basic state within the same sub-journey",
      sourceState: BASIC_PAGE_STATE,
      targetState: BASIC_CRI_STATE,
      currentSubJourney: FIRST_SUB_JOURNEY,
      allTargetStates: [BASIC_CRI_STATE],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: NESTED_JOURNEY_ENTRY_STATE_1,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_CRI_STATE,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is an entry state for a first sub-journey and the targetState is a basic state within the same sub-journey",
      sourceState: ENTRY_STATE_TO_BASIC_PAGE_STATE,
      targetState: BASIC_PAGE_STATE,
      currentSubJourney: FIRST_SUB_JOURNEY,
      allTargetStates: [BASIC_PAGE_STATE],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: ENTRY_STATE_TO_BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_CRI_STATE,
        }),
      ],
      expectedCount: 1,
    },
    {
      testCase:
        "the sourceState is a nested journey state and the targetState is a basic state in the same sub-journey",
      sourceState: NESTED_JOURNEY_ENTRY_STATE_1,
      targetState: BASIC_PAGE_STATE,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [BASIC_PAGE_STATE],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is a nested journey state and the targetState is a nested journey state within the same sub-journey",
      sourceState: NESTED_JOURNEY_ENTRY_STATE_1,
      targetState: NESTED_JOURNEY_ENTRY_STATE_2,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [NESTED_JOURNEY_ENTRY_STATE_2],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE_2`,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE/DOUBLE_NESTED_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is an entry state for an intermediate sub-journey and the targetState is a basic state",
      sourceState: ENTRY_STATE_TO_BASIC_PAGE_STATE,
      targetState: BASIC_PAGE_STATE,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [BASIC_PAGE_STATE],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_2,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is an entry state for an intermediate sub-journey and the targetState is a nested journey state",
      sourceState: ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1,
      targetState: NESTED_JOURNEY_ENTRY_STATE_1,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [NESTED_JOURNEY_ENTRY_STATE_1],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_2,
          from: `${NESTED_JOURNEY_ENTRY_STATE_2}/ANOTHER_INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
      ],
      expectedCount: 3,
    },
    {
      testCase:
        "the sourceState is an entry state for an intermediate journey and the targetState is a nested journey state in the same sub-journey - targetState is from a conditional check",
      sourceState: ENTRY_STATE_WITH_MULTIPLE_TARGET_STATES,
      targetState: NESTED_JOURNEY_ENTRY_STATE_1,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [
        BASIC_PAGE_STATE,
        NESTED_JOURNEY_ENTRY_STATE_1,
        BASIC_CRI_STATE,
      ],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_2,
          from: NESTED_JOURNEY_ENTRY_STATE_2,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_2,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is an entry state for a first sub-journey and the targetState is a basic state in the same sub-journey",
      sourceState: ENTRY_STATE_TO_BASIC_PAGE_STATE,
      targetState: BASIC_PAGE_STATE,
      currentSubJourney: FIRST_SUB_JOURNEY,
      allTargetStates: [BASIC_PAGE_STATE],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_PAGE_STATE,
        }),
      ],
      expectedCount: 1,
    },
    {
      testCase:
        "the sourceState is an entry state for a first sub-journey and the targetState is a nested journey state in the same sub-journey",
      sourceState: ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1,
      targetState: NESTED_JOURNEY_ENTRY_STATE_1,
      currentSubJourney: FIRST_SUB_JOURNEY,
      allTargetStates: [NESTED_JOURNEY_ENTRY_STATE_1],
      journeyTraffic: [
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1,
          toJourney: FIRST_SUB_JOURNEY,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1,
          toJourney: FIRST_SUB_JOURNEY,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: FIRST_SUB_JOURNEY,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is an entry state for a first sub-journey and the targetState is a basic state in a new sub-journey",
      sourceState: ENTRY_STATE_TO_BASIC_STATE_IN_NEW_SUB_JOURNEY,
      targetState: `${SUB_JOURNEY_1}__${ENTRY_STATE_TO_BASIC_PAGE_STATE}`,
      currentSubJourney: FIRST_SUB_JOURNEY,
      allTargetStates: [`${SUB_JOURNEY_1}__${ENTRY_STATE_TO_BASIC_PAGE_STATE}`],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_BASIC_STATE_IN_NEW_SUB_JOURNEY,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_BASIC_STATE_IN_NEW_SUB_JOURNEY,
          toJourney: SUB_JOURNEY_2,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_BASIC_STATE_IN_NEW_SUB_JOURNEY,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_CRI_STATE,
        }),
      ],
      expectedCount: 1,
    },
    {
      testCase:
        "the sourceState is an entry state for a first sub-journey and the targetState is a new sub-journey with multiple targets",
      sourceState: ENTRY_STATE_TO_NEW_SUB_JOURNEY_WITH_MULTIPLE_TARGET_STATES,
      targetState: `${SUB_JOURNEY_1}__${ENTRY_STATE_WITH_MULTIPLE_TARGET_STATES}`,
      currentSubJourney: FIRST_SUB_JOURNEY,
      allTargetStates: [
        BASIC_CRI_STATE,
        BASIC_PAGE_STATE,
        NESTED_JOURNEY_ENTRY_STATE_1,
      ],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NEW_SUB_JOURNEY_WITH_MULTIPLE_TARGET_STATES,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NEW_SUB_JOURNEY_WITH_MULTIPLE_TARGET_STATES,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NEW_SUB_JOURNEY_WITH_MULTIPLE_TARGET_STATES,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NEW_SUB_JOURNEY_WITH_MULTIPLE_TARGET_STATES,
          toJourney: SUB_JOURNEY_2,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_CRI_STATE,
        }),
      ],
      expectedCount: 3,
    },
    {
      testCase:
        "the sourceState is an entry state for a first sub-journey and the targetState is a nested state in a new sub-journey",
      sourceState: ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY,
      targetState: `${SUB_JOURNEY_1}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      currentSubJourney: FIRST_SUB_JOURNEY,
      allTargetStates: [
        `${SUB_JOURNEY_1}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      ],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY,
          toJourney: SUB_JOURNEY_1,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: FIRST_SUB_JOURNEY,
          from: BASIC_PAGE_STATE,
          toJourney: FIRST_SUB_JOURNEY,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_2,
          from: ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is a basic state and the targetState is a basic state in a new sub-journey",
      sourceState: NESTED_JOURNEY_ENTRY_STATE_1,
      targetState: `${SUB_JOURNEY_2}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [
        `${SUB_JOURNEY_2}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      ],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/ALTERNATE_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ALTERNATE_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/ALTERNATE_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/ALTERNATE_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ALTERNATE_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ALTERNATE_STATE`,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is a basic state and the targetState is a nested journey state in a new sub-journey",
      sourceState: BASIC_CRI_STATE,
      targetState: `${SUB_JOURNEY_2}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [
        `${SUB_JOURNEY_2}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      ],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is a basic state and the targetState is to a new sub-journey where the entry state has multiple targets",
      sourceState: BASIC_CRI_STATE,
      targetState: `${SUB_JOURNEY_2}__${ENTRY_STATE_WITH_MULTIPLE_TARGET_STATES}`,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [
        BASIC_CRI_STATE,
        BASIC_PAGE_STATE,
        NESTED_JOURNEY_ENTRY_STATE_1,
      ],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_2,
          to: BASIC_PAGE_STATE,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_2,
          to: BASIC_CRI_STATE,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: BASIC_CRI_STATE,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
      ],
      expectedCount: 4,
    },
    {
      testCase:
        "the sourceState is a nested journey state and the targetState is a basic state in a new sub-journey",
      sourceState: NESTED_JOURNEY_ENTRY_STATE_1,
      targetState: `${SUB_JOURNEY_2}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [
        `${SUB_JOURNEY_2}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      ],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_2,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
      ],
      expectedCount: 2,
    },
    {
      testCase:
        "the sourceState is a nested journey state and the targetState is a nested journey state in a new sub-journey",
      sourceState: NESTED_JOURNEY_ENTRY_STATE_1,
      targetState: `${SUB_JOURNEY_2}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      currentSubJourney: SUB_JOURNEY_1,
      allTargetStates: [
        `${SUB_JOURNEY_2}__${ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1}`,
      ],
      journeyTraffic: [
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          // Valid transition
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_2}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_2,
          from: BASIC_PAGE_STATE,
          toJourney: SUB_JOURNEY_2,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
        }),
        createTraffic({
          fromJourney: SUB_JOURNEY_1,
          from: `${NESTED_JOURNEY_ENTRY_STATE_1}/INTERNAL_STATE`,
          toJourney: SUB_JOURNEY_1,
          to: `${NESTED_JOURNEY_ENTRY_STATE_1}/ANOTHER_INTERNAL_STATE`,
        }),
      ],
      expectedCount: 2,
    },
  ])(
    "should return the correct transition count when $testCase",
    ({
      sourceState,
      targetState,
      currentSubJourney,
      allTargetStates,
      journeyTraffic,
      expectedCount,
    }) => {
      const transitionCount =
        getTransitionCountFromSubJourneyStateToTargetState(
          JOURNEY_STATES,
          currentSubJourney,
          JOURNEY_MAPS,
          journeyTraffic,
          sourceState,
          targetState,
          allTargetStates,
        );
      expect(transitionCount).toEqual(expectedCount);
    },
  );
});

const FIRST_SUB_JOURNEY = "FIRST_SUB_JOURNEY";
const SUB_JOURNEY_1 = "SUB_JOURNEY_1";
const SUB_JOURNEY_2 = "SUB_JOURNEY_2";

const BASIC_PAGE_STATE = "BASIC_PAGE_STATE";
const BASIC_CRI_STATE = "BASIC_CRI_STATE";
const NESTED_JOURNEY_ENTRY_STATE_1 = "NESTED_JOURNEY_ENTRY_STATE_1";
const NESTED_JOURNEY_ENTRY_STATE_2 = "NESTED_JOURNEY_ENTRY_STATE_2";
const ENTRY_STATE_TO_BASIC_PAGE_STATE = "ENTRY_STATE_TO_BASIC_PAGE_STATE";
const ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1 =
  "ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1";
const ENTRY_STATE_TO_BASIC_STATE_IN_NEW_SUB_JOURNEY =
  "ENTRY_STATE_TO_BASIC_STATE_IN_NEW_SUB_JOURNEY";
const ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY =
  "ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY";
const ENTRY_STATE_WITH_MULTIPLE_TARGET_STATES =
  "ENTRY_STATE_WITH_MULTIPLE_TARGET_STATES";
const ENTRY_STATE_TO_NEW_SUB_JOURNEY_WITH_MULTIPLE_TARGET_STATES =
  "ENTRY_STATE_TO_NEW_SUB_JOURNEY_WITH_MULTIPLE_TARGET_STATES";

const JOURNEY_STATES = {
  [ENTRY_STATE_WITH_MULTIPLE_TARGET_STATES]: {
    events: {
      next: {
        targetState: BASIC_PAGE_STATE,
        checkMitigation: {
          mitigation: {
            targetState: NESTED_JOURNEY_ENTRY_STATE_1,
          },
        },
        checkFeatureFlag: {
          featureFlag: {
            targetState: BASIC_CRI_STATE,
          },
        },
      },
    },
  },
  [ENTRY_STATE_TO_BASIC_PAGE_STATE]: {
    events: {
      next: {
        targetState: BASIC_PAGE_STATE,
      },
    },
  },
  [ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1]: {
    events: {
      next: {
        targetState: NESTED_JOURNEY_ENTRY_STATE_1,
      },
    },
  },
  [ENTRY_STATE_TO_BASIC_STATE_IN_NEW_SUB_JOURNEY]: {
    events: {
      next: {
        targetJourney: SUB_JOURNEY_1,
        targetState: ENTRY_STATE_TO_BASIC_PAGE_STATE,
      },
    },
  },
  [ENTRY_STATE_TO_NESTED_STATE_IN_NEW_SUB_JOURNEY]: {
    events: {
      next: {
        targetJourney: SUB_JOURNEY_1,
        targetState: ENTRY_STATE_TO_NESTED_JOURNEY_STATE_1,
      },
    },
  },
  [ENTRY_STATE_TO_NEW_SUB_JOURNEY_WITH_MULTIPLE_TARGET_STATES]: {
    events: {
      next: {
        targetJourney: SUB_JOURNEY_1,
        targetState: ENTRY_STATE_WITH_MULTIPLE_TARGET_STATES,
      },
    },
  },
  [BASIC_PAGE_STATE]: {
    response: {
      type: "page",
    },
  },
  [BASIC_CRI_STATE]: {
    response: {
      type: "cri",
    },
  },
  [NESTED_JOURNEY_ENTRY_STATE_1]: {
    response: {
      type: "nestedJourney",
    },
  },
  [NESTED_JOURNEY_ENTRY_STATE_2]: {
    response: {
      type: "nestedJourney",
    },
  },
} as Record<string, JourneyState>;

const JOURNEY_MAPS = {
  [FIRST_SUB_JOURNEY]: {
    name: "FIRST_SUB_JOURNEY",
    description: "description",
    states: JOURNEY_STATES,
  },
  [SUB_JOURNEY_1]: {
    name: "SUB_JOURNEY_1",
    description: "description",
    states: JOURNEY_STATES,
  },
  [SUB_JOURNEY_2]: {
    name: "SUB_JOURNEY_2",
    description: "description",
    states: JOURNEY_STATES,
  },
};

const createTraffic = (
  transitionsDetails: Omit<JourneyTransition, "count" | "event">,
): JourneyTransition => ({
  ...transitionsDetails,
  event: "an-arbitrary-event",
  count: 1,
});
