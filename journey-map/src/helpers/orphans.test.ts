import { describe, it } from "node:test";
import assert from "node:assert";
import yaml from "yaml";
import { findOrphanStates } from "./orphans.js";
import { JourneyState } from "../types.js";

describe("findOrphanStates", () => {
  it("should find orphaned states", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetState: NOT_ORPHAN
      NOT_ORPHAN:
        response:
          type: page
          pageId: test-page
      ORPHAN:
        response:
          type: page
          pageId: test-page
      `);

    // Act
    const actual = findOrphanStates(states);

    // Assert
    assert.strictEqual(actual.length, 2);
    assert.strictEqual(actual[0].name, "ENTRY_STATE");
    assert.strictEqual(actual[1].name, "ORPHAN");
  });

  it("should not include states referenced via checks", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetState: DIRECT
            checkIfDisabled:
              test:
                targetState: DISABLED
            checkJourneyContext:
              test:
                targetState: JOURNEY_CONTEXT
            checkFeatureFlag:
              test:
                targetState: FEATURE_FLAG
            checkMitigation:
              test:
                targetState: MITIGATION
      DIRECT:
        response:
          type: page
          pageId: test-page
      DISABLED:
        response:
          type: page
          pageId: test-page
      JOURNEY_CONTEXT:
        response:
          type: page
          pageId: test-page
      FEATURE_FLAG:
        response:
          type: page
          pageId: test-page
      MITIGATION:
        response:
          type: page
          pageId: test-page
      ORPHAN:
        response:
          type: page
          pageId: test-page
      `);

    // Act
    const actual = findOrphanStates(states);

    // Assert
    assert.strictEqual(actual.length, 2);
    assert.strictEqual(actual[0].name, "ENTRY_STATE");
    assert.strictEqual(actual[1].name, "ORPHAN");
  });

  it("should include states even if they are referenced in other journeys", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetJourney: OTHER_JOURNEY
            targetState: ORPHAN
      ORPHAN:
        response:
          type: page
          pageId: test-page
      `);

    // Act
    const actual = findOrphanStates(states);

    // Assert
    assert.strictEqual(actual.length, 2);
    assert.strictEqual(actual[0].name, "ENTRY_STATE");
    assert.strictEqual(actual[1].name, "ORPHAN");
  });
});
