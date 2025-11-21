import { describe, it, expect } from "vitest";
import yaml from "yaml";
import { JourneyEvent, JourneyState } from "../types.js";
import {
  resolveAllEventTargets,
  resolveAllTargets,
  resolveVisibleEventTargets,
} from "./event-resolver.js";
import { RenderOptions } from "./options.js";

const DEFAULT_OPTIONS: RenderOptions = {
  disabledCris: ["test-cri"],
  featureFlags: ["test-feature"],
  includeErrors: false,
  includeFailures: false,
  expandNestedJourneys: false,
  onlyOrphanStates: false,
};

describe("resolveAllEventTargets", () => {
  it("should resolve all event targets from an event", () => {
    // Arrange
    const event: JourneyEvent = yaml.parse(`
      targetState: SOME_TARGET
      checkIfDisabled:
        test-cri:
          targetState: DISABLED_TARGET
      checkJourneyContext:
        test-context:
          targetState: JOURNEY_TARGET
      checkFeatureFlag:
        test-feature:
          targetState: FEATURE_TARGET
      checkMitigation:
        test-mitigation:
          targetState: MITIGATION_TARGET
    `);

    const expected = [
      { targetState: "SOME_TARGET" },
      { targetState: "DISABLED_TARGET" },
      { targetState: "JOURNEY_TARGET" },
      { targetState: "FEATURE_TARGET" },
      { targetState: "MITIGATION_TARGET" },
    ];

    // Act
    const actual = resolveAllEventTargets(event);

    // Assert
    expect(actual).toMatchObject(expected);
  });

  it("should resolve deeply nested event targets", () => {
    // Arrange
    const event: JourneyEvent = yaml.parse(`
      targetState: SOME_TARGET
      checkIfDisabled:
        test-cri:
          targetState: DISABLED_TARGET
          checkJourneyContext:
            test-context:
              targetState: JOURNEY_TARGET
              checkFeatureFlag:
                test-feature:
                  targetState: FEATURE_TARGET
                  checkMitigation:
                    test-mitigation:
                      targetState: MITIGATION_TARGET
    `);

    const expected = [
      { targetState: "SOME_TARGET" },
      { targetState: "DISABLED_TARGET" },
      { targetState: "JOURNEY_TARGET" },
      { targetState: "FEATURE_TARGET" },
      { targetState: "MITIGATION_TARGET" },
    ];

    // Act
    const actual = resolveAllEventTargets(event);

    // Assert
    expect(actual).toMatchObject(expected);
  });
});

describe("resolveAllTargets", () => {
  it("should resolve all targets from all states", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      SOME_STATE:
        events:
          next:
            targetState: SOME_TARGET
      SOME_OTHER_STATE:
        events:
          next:
            targetState: SOME_OTHER_TARGET
      END_EVENT:
        response:
          type: page
          pageId: test-page
    `);

    const expected = [
      { targetState: "SOME_TARGET" },
      { targetState: "SOME_OTHER_TARGET" },
    ];

    // Act
    const actual = resolveAllTargets(states);

    // Assert
    expect(actual).toMatchObject(expected);
  });

  it("should resolve targets from exit events", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      SOME_STATE:
        nestedJourney: NESTED_JOURNEY
        exitEvents:
          next:
            targetState: SOME_TARGET
    `);

    const expected = [{ targetState: "SOME_TARGET" }];

    // Act
    const actual = resolveAllTargets(states);

    // Assert
    expect(actual).toMatchObject(expected);
  });
});

describe("resolveVisibleEventTargets", () => {
  it("should resolve standard event targets from an event", () => {
    // Arrange
    const event: JourneyEvent = yaml.parse(`
      targetState: SOME_TARGET
    `);

    const expected = [{ targetState: "SOME_TARGET" }];

    // Act
    const actual = resolveVisibleEventTargets(event, DEFAULT_OPTIONS);

    // Assert
    expect(actual).toMatchObject(expected);
  });

  it("should resolve event targets behind a disabled check", () => {
    // Arrange
    const event: JourneyEvent = yaml.parse(`
      targetState: SOME_TARGET
      checkIfDisabled:
        test-cri:
          targetState: DISABLED_TARGET
    `);

    const expected = [{ targetState: "DISABLED_TARGET" }];

    // Act
    const actual = resolveVisibleEventTargets(event, DEFAULT_OPTIONS);

    // Assert
    expect(actual).toMatchObject(expected);
  });

  it("should resolve event targets behind a feature flag", () => {
    // Arrange
    const event: JourneyEvent = yaml.parse(`
      targetState: SOME_TARGET
      checkFeatureFlag:
        test-feature:
          targetState: FEATURE_TARGET
    `);

    const expected = [{ targetState: "FEATURE_TARGET" }];

    // Act
    const actual = resolveVisibleEventTargets(event, DEFAULT_OPTIONS);

    // Assert
    expect(actual).toMatchObject(expected);
  });

  it("should resolve all journey context targets and add journeyContext", () => {
    // Arrange
    const event: JourneyEvent = yaml.parse(`
      targetState: SOME_TARGET
      checkJourneyContext:
        test-context:
          targetState: CONTEXT_TARGET
    `);

    const expected = [
      { targetState: "CONTEXT_TARGET", journeyContext: "test-context" },
      { targetState: "SOME_TARGET" },
    ];

    // Act
    const actual = resolveVisibleEventTargets(event, DEFAULT_OPTIONS);

    // Assert
    expect(actual).toMatchObject(expected);
  });

  it("should resolve all mitigation targets and add mitigation", () => {
    // Arrange
    const event: JourneyEvent = yaml.parse(`
      targetState: SOME_TARGET
      checkMitigation:
        test-mitigation:
          targetState: MITIGATION_TARGET
    `);

    const expected = [
      { targetState: "MITIGATION_TARGET", mitigation: "test-mitigation" },
      { targetState: "SOME_TARGET" },
    ];

    // Act
    const actual = resolveVisibleEventTargets(event, DEFAULT_OPTIONS);

    // Assert
    expect(actual).toMatchObject(expected);
  });

  it("should resolve nested targets and propagate journeyContext and mitigations", () => {
    // Arrange
    const event: JourneyEvent = yaml.parse(`
      targetState: SOME_TARGET
      checkIfDisabled:
        test-cri:
          targetState: DISABLED_TARGET
          checkJourneyContext:
            test-context:
              targetState: JOURNEY_TARGET
              checkFeatureFlag:
                test-feature:
                  targetState: FEATURE_TARGET
                  checkMitigation:
                    test-mitigation:
                      targetState: MITIGATION_TARGET
    `);

    const expected = [
      {
        targetState: "MITIGATION_TARGET",
        journeyContext: "test-context",
        mitigation: "test-mitigation",
      },
      { targetState: "FEATURE_TARGET", journeyContext: "test-context" },
      // { targetState: "JOURNEY_TARGET" }, // Excluded because the feature flag takes priority
      { targetState: "DISABLED_TARGET" },
      // { targetState: "SOME_TARGET" }, // Excluded because disabled flag takes priority
    ];

    // Act
    const actual = resolveVisibleEventTargets(event, DEFAULT_OPTIONS);

    // Assert
    expect(actual).toMatchObject(expected);
  });
});
