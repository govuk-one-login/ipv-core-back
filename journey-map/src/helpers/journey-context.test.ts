import { describe, it, expect } from "vitest";
import yaml from "yaml";
import { JourneyState } from "../types.js";
import { getJourneyContexts } from "./journey-context.js";

describe("getJourneyContexts", () => {
  it("should find journey contexts in use", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetState: END_STATE
            checkJourneyContext:
              context-one:
                targetState: OTHER_STATE
              context-two:
                targetState: OTHER_STATE
      `);

    const expected = ["context-one", "context-two"];

    // Act
    const actual = getJourneyContexts(states);

    // Assert
    expect(actual).toEqual(expected);
  });

  it("should find journey contexts in nested conditions", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetState: OTHER_STATE
            checkIfDisabled:
              test-cri:
                targetState: OTHER_STATE
                checkJourneyContext:
                  test-context:
                    targetState: OTHER_STATE
      `);

    const expected = ["test-context"];

    // Act
    const actual = getJourneyContexts(states);

    // Assert
    expect(actual).toEqual(expected);
  });

  it("should deduplicate", () => {
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetState: END_STATE
            checkJourneyContext:
              test-context:
                targetState: OTHER_STATE
      OTHER_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetState: END_STATE
            checkJourneyContext:
              test-context:
                targetState: OTHER_STATE
      `);

    const expected = ["test-context"];

    // Act
    const actual = getJourneyContexts(states);

    // Assert
    expect(actual).toEqual(expected);
  });
});
