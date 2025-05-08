import { describe, it } from "node:test";
import assert from "node:assert";
import yaml from "yaml";
import { getAsFullJourneyMap } from "./uplift-nested.js";
import { JourneyMap, NestedJourneyMap } from "../types.js";

describe("getAsFullJourneyMap", () => {
  it("should add synthetic entry events", () => {
    // Arrange
    const original: NestedJourneyMap = yaml.parse(`
      name: Test
      description: A test nested journey
      entryEvents:
        next:
          targetState: FIRST_STATE
        other:
          targetState: FIRST_STATE
          checkIfDisabled:
            foo:
              targetState: SECOND_STATE
      nestedJourneyStates:
        FIRST_STATE:
          response:
            type: page
            pageId: test-page
        SECOND_STATE:
          response:
            type: page
            pageId: test-page
      `);
    const expected: JourneyMap = yaml.parse(`
      name: Test
      description: A test nested journey
      states:
        ENTRY_NEXT:
          entryEvent: next
          events:
            next:
              targetState: FIRST_STATE
        ENTRY_OTHER:
          entryEvent: other
          events:
            other:
              targetState: FIRST_STATE
              checkIfDisabled:
                foo:
                  targetState: SECOND_STATE
        FIRST_STATE:
          response:
            type: page
            pageId: test-page
        SECOND_STATE:
          response:
            type: page
            pageId: test-page
      `);

    // Act
    const actual = getAsFullJourneyMap(original);

    // Assert
    assert.deepEqual(actual, expected);
  });

  it("should add synthetic exit events", () => {
    // Arrange
    const original: NestedJourneyMap = yaml.parse(`
      name: Test
      description: A test nested journey
      entryEvents:
        next:
          targetState: FIRST_STATE
      nestedJourneyStates:
        FIRST_STATE:
          response:
            type: page
            pageId: test-page
          events:
            next:
              exitEventToEmit: first
              checkIfDisabled:
                foo:
                  exitEventToEmit: second
      `);
    const expected: JourneyMap = yaml.parse(`
      name: Test
      description: A test nested journey
      states:
        ENTRY_NEXT:
          entryEvent: next
          events:
            next:
              targetState: FIRST_STATE
        FIRST_STATE:
          response:
            type: page
            pageId: test-page
          events:
            next:
              targetState: EXIT_FIRST
              checkIfDisabled:
                foo:
                  targetState: EXIT_SECOND
        EXIT_FIRST:
          exitEvent: first
        EXIT_SECOND:
          exitEvent: second
      `);

    // Act
    const actual = getAsFullJourneyMap(original);

    // Assert
    assert.deepEqual(actual, expected);
  });
});
