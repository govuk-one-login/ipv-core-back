import { describe, it } from "node:test";
import assert from "node:assert";
import yaml from "yaml";
import { JourneyState } from "../types.js";
import { addJourneyTransitions } from "./add-journey-transitions.js";

describe("addJourneyTransitions", () => {
  it("should add synthetic states for journey transitions", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NEW_STATE
            targetJourney: NEW_JOURNEY
      `);

    const expected: Record<string, JourneyState> = yaml.parse(`
      ENTRY_STATE:
        events:
          next:
            targetState: NEW_JOURNEY__NEW_STATE
      NEW_JOURNEY__NEW_STATE:
        response:
          type: journeyTransition
          targetJourney: NEW_JOURNEY
          targetState: NEW_STATE
    `);

    // Act
    addJourneyTransitions(states);

    // Assert
    assert.deepEqual(states, expected);
  });
});
