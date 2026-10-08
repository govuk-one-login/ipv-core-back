import { describe, it, expect, vi } from "vitest";
import yaml from "yaml";
import { JourneyState } from "../types.js";
import { expandParents } from "./expand-parents.js";

describe("expandParents", () => {
  it("should expand parent events", () => {
    // Arrange
    const original: Record<string, JourneyState> = yaml.parse(`
      PARENT:
        events:
          foo:
            targetState: FOO
          bar:
            targetState: BAR
      FIRST_STATE:
        parent: PARENT
        response:
          type: page
          pageId: test-page
      SECOND_STATE:
        parent: PARENT
        response:
          type: page
          pageId: test-page
        events:
          baz:
            targetState: BAZ
      `);
    const expected: Record<string, JourneyState> = yaml.parse(`
      FIRST_STATE:
        response:
          type: page
          pageId: test-page
        events:
          foo:
            targetState: FOO
          bar:
            targetState: BAR
      SECOND_STATE:
        response:
          type: page
          pageId: test-page
        events:
          foo:
            targetState: FOO
          bar:
            targetState: BAR
          baz:
            targetState: BAZ
      `);

    // Act
    expandParents(original, {});

    // Assert
    expect(original).toEqual(expected);
  });

  it("should expand parent events from other states", () => {
    // Arrange
    const original: Record<string, JourneyState> = yaml.parse(`
      FIRST_STATE:
        parent: PARENT
        response:
          type: page
          pageId: test-page
      `);
    const other: Record<string, JourneyState> = yaml.parse(`
        PARENT:
          events:
            foo:
              targetState: FOO
            bar:
              targetState: BAR
        `);
    const expected: Record<string, JourneyState> = yaml.parse(`
      FIRST_STATE:
        response:
          type: page
          pageId: test-page
        events:
          foo:
            targetState: FOO
          bar:
            targetState: BAR
      `);

    // Act
    expandParents(original, other);

    // Assert
    expect(original).toEqual(expected);
  });

  it("throws when a state references a parent that does not exist", () => {
    // Arrange
    const original: Record<string, JourneyState> = yaml.parse(`
      FIRST_STATE:
        parent: MISSING_PARENT
        response:
          type: page
          pageId: test-page
      `);
    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => undefined);

    try {
      // Act & Assert
      expect(() => expandParents(original, {})).toThrow(
        '"undefined" is not valid JSON',
      );

      expect(warnSpy).toHaveBeenCalledWith(
        "Missing parent MISSING_PARENT of state FIRST_STATE",
      );
    } finally {
      warnSpy.mockRestore();
    }
  });
});
