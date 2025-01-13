export interface ObjectPartialEqualityResult {
  isPartiallyEqual: boolean;
  errorMessage?: string;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
export const comparePartialEqualityBetweenObjects = (
  actualObject: Record<string, any>,
  expectedObject: Record<string, any>,
): ObjectPartialEqualityResult => {
  for (const [expectedKey, expectedValue] of Object.entries(expectedObject)) {
    if (actualObject[expectedKey] === undefined) {
      return {
        isPartiallyEqual: false,
        errorMessage: `Expected ${expectedKey} to be a property in ${actualObject}`,
      };
    }

    if (
      expectedValue instanceof Object &&
      actualObject[expectedKey] instanceof Object
    ) {
      const isEqual = comparePartialEqualityBetweenObjects(
        actualObject[expectedKey],
        expectedValue,
      );

      if (!isEqual.isPartiallyEqual) {
        return isEqual;
      }
      continue;
    }

    if (expectedValue !== actualObject[expectedKey]) {
      return {
        isPartiallyEqual: false,
        errorMessage: `Expected ${expectedValue} for field ${expectedKey} but got ${actualObject[expectedKey]}`,
      };
    }
  }
  return { isPartiallyEqual: true };
};
