import { describe, it, expect } from "vitest";
import yaml from "yaml";
import { JourneyState, NestedJourneyMap } from "../types.js";
import { expandNestedJourneys } from "./expand-nested.js";

describe("expandNested", () => {
  it("should expand nested journeys with an implicit entry event", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE
      NESTED_STATE:
        nestedJourney: TEST_NESTED
        exitEvents:
          next:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    const nestedDefinition: NestedJourneyMap = yaml.parse(`
      name: Test
      description: Test nested journey
      entryEvents:
        next:
          targetState: FIRST_STATE
      nestedJourneyStates:
        FIRST_STATE:
          response:
            type: page
            pageId: test-page
          events:
            nestedNext:
              exitEventToEmit: next
    `);

    const expected: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE/FIRST_STATE
      NESTED_STATE/FIRST_STATE:
        response:
          type: page
          pageId: test-page
        events:
          nestedNext:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    // Act
    expandNestedJourneys(states, { TEST_NESTED: nestedDefinition });

    // Assert
    expect(states).toEqual(expected);
  });

  it("should expand nested journeys with an explicit entry event", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE
            targetEntryEvent: other
      NESTED_STATE:
        nestedJourney: TEST_NESTED
        exitEvents:
          next:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    const nestedDefinition: NestedJourneyMap = yaml.parse(`
      name: Test
      description: Test nested journey
      entryEvents:
        next:
          targetState: FIRST_STATE
        other:
          targetState: SECOND_STATE
      nestedJourneyStates:
        FIRST_STATE:
          response:
            type: page
            pageId: test-page
          events:
            nestedNext:
              exitEventToEmit: next
        SECOND_STATE:
          response:
            type: page
            pageId: test-page
          events:
            nestedNext:
              exitEventToEmit: next
    `);

    const expected: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE/SECOND_STATE
      NESTED_STATE/FIRST_STATE:
        response:
          type: page
          pageId: test-page
        events:
          nestedNext:
            targetState: END_STATE
      NESTED_STATE/SECOND_STATE:
        response:
          type: page
          pageId: test-page
        events:
          nestedNext:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    // Act
    expandNestedJourneys(states, { TEST_NESTED: nestedDefinition });

    // Assert
    expect(states).toEqual(expected);
  });

  it("should expand nested journeys behind conditions", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE
            checkIfDisabled:
              test-cri:
                targetState: NESTED_STATE
            checkJourneyContext:
              test-context:
                targetState: NESTED_STATE
            checkFeatureFlag:
              test-feature:
                targetState: NESTED_STATE
            checkMitigation:
              test-mitigation:
                targetState: NESTED_STATE
      NESTED_STATE:
        nestedJourney: TEST_NESTED
        exitEvents:
          next:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    const nestedDefinition: NestedJourneyMap = yaml.parse(`
      name: Test
      description: Test nested journey
      entryEvents:
        next:
          targetState: FIRST_STATE
      nestedJourneyStates:
        FIRST_STATE:
          response:
            type: page
            pageId: test-page
          events:
            nestedNext:
              exitEventToEmit: next
    `);

    const expected: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE/FIRST_STATE
            checkIfDisabled:
              test-cri:
                targetState: NESTED_STATE/FIRST_STATE
            checkJourneyContext:
              test-context:
                targetState: NESTED_STATE/FIRST_STATE
            checkFeatureFlag:
              test-feature:
                targetState: NESTED_STATE/FIRST_STATE
            checkMitigation:
              test-mitigation:
                targetState: NESTED_STATE/FIRST_STATE
      NESTED_STATE/FIRST_STATE:
        response:
          type: page
          pageId: test-page
        events:
          nestedNext:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    // Act
    expandNestedJourneys(states, { TEST_NESTED: nestedDefinition });

    // Assert
    expect(states).toEqual(expected);
  });

  it("should expand doubly-nested journeys", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE
      NESTED_STATE:
        nestedJourney: OUTER_NESTED
        exitEvents:
          next:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    const outerNestedDefinition: NestedJourneyMap = yaml.parse(`
      name: Outer test
      description: Test nested journey
      entryEvents:
        next:
          targetState: OUTER_FIRST_STATE
      nestedJourneyStates:
        OUTER_FIRST_STATE:
          nestedJourney: INNER_NESTED
          exitEvents:
            outerNestedNext:
              exitEventToEmit: next
    `);

    const innerNestedDefinition: NestedJourneyMap = yaml.parse(`
      name: Inner test
      description: Test nested journey
      entryEvents:
        next:
          targetState: INNER_FIRST_STATE
      nestedJourneyStates:
        INNER_FIRST_STATE:
          response:
            type: page
            pageId: test-page
          events:
            innerNestedNext:
              exitEventToEmit: outerNestedNext
    `);

    const expected: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE/OUTER_FIRST_STATE/INNER_FIRST_STATE
      NESTED_STATE/OUTER_FIRST_STATE/INNER_FIRST_STATE:
        response:
          type: page
          pageId: test-page
        events:
          innerNestedNext:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    const nestedJourneys = {
      OUTER_NESTED: outerNestedDefinition,
      INNER_NESTED: innerNestedDefinition,
    };

    // Act
    expandNestedJourneys(states, nestedJourneys);

    // Assert
    expect(states).toEqual(expected);
  });

  it("should expand chained nested journeys", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE_ONE
      NESTED_STATE_ONE:
        nestedJourney: TEST_NESTED
        exitEvents:
          next:
            targetState: NESTED_STATE_TWO
      NESTED_STATE_TWO:
        nestedJourney: TEST_NESTED
        exitEvents:
          next:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    const nestedDefinition: NestedJourneyMap = yaml.parse(`
      name: Test
      description: Test nested journey
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
              exitEventToEmit: next
    `);

    const expected: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NESTED_STATE_ONE/FIRST_STATE
      NESTED_STATE_ONE/FIRST_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetState: NESTED_STATE_TWO/FIRST_STATE
      NESTED_STATE_TWO/FIRST_STATE:
        response:
          type: page
          pageId: test-page
        events:
          next:
            targetState: END_STATE
      END_STATE:
        response:
          type: page
          pageId: test-page
    `);

    // Act
    expandNestedJourneys(states, { TEST_NESTED: nestedDefinition });

    // Assert
    expect(states).toEqual(expected);
  });
});
