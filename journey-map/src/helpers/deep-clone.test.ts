import { describe, it, expect } from "vitest";
import { deepCloneJson } from "./deep-clone.js";

describe("deepCloneJson", () => {
  it("should produce identical clones", () => {
    // Arrange
    const obj = {
      foo: {
        bar: 5,
      },
      baz: "hello",
    };

    // Act
    const cloned = deepCloneJson(obj);

    // Assert
    expect(cloned).toStrictEqual(obj);
  });

  it("should produce independent clones", () => {
    // Arrange
    const obj = {
      foo: {
        bar: 5,
      },
    };
    const cloned = deepCloneJson(obj);

    // Act
    cloned.foo.bar = 10;

    // Assert
    expect(obj.foo.bar).toEqual(5);
    expect(cloned.foo.bar).toEqual(10);
  });
});
