import { describe, it } from "node:test";
import assert from "node:assert";
import yaml from "yaml";
import { JourneyState } from "../types.js";
import { contractNestedJourneys } from "./contract-nested.js";

describe("contractNestedJourneys", () => {
  it("should convert nested journeys to a synthetic response", () => {
    // Arrange
    const states: Record<string, JourneyState> = yaml.parse(`
      TEST_STATE:
        nestedJourney: someJourney
        exitEvents:
          next:
            targetState: NEW_STATE
      `);

    const expected: Record<string, JourneyState> = yaml.parse(`
      TEST_STATE:
        response:
          type: nestedJourney
          nestedJourney: someJourney
        events:
          next:
            targetState: NEW_STATE
    `);

    // Act
    contractNestedJourneys(states);

    // Assert
    assert.deepEqual(states, expected);
  });
});
