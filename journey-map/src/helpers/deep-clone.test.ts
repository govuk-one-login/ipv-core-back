import { describe, it } from "node:test";
import assert from "node:assert";
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
    assert.deepEqual(obj, cloned);
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
    assert.equal(obj.foo.bar, 5);
    assert.equal(cloned.foo.bar, 10);
  });
});
