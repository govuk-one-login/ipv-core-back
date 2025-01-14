export interface ObjectPartialEqualityResult {
  isPartiallyEqual: boolean;
  errorMessage?: string;
}

enum SupportedTypeMatchers {
  "string",
  "number",
}

const TYPE_CHECK_REGEX = /^type\[(\w+)\]$/;

// In node v23, there is a feature called partialDeepStrictEqual which does what we want
// However, since we are on node v22, we create a partial matcher from scratch.
// When we upgrade to node >=v23, we could replace this matcher with partialDeepStrictEqual instead.
// Read up on docs for the feature here: https://nodejs.org/api/assert.html#assertpartialdeepstrictequalactual-expected-message
/* eslint-disable @typescript-eslint/no-explicit-any */
export const comparePartialEqualityBetweenObjects = (
  actualObject: Record<string, any>,
  expectedObject: Record<string, any>,
  objectKeyHistory: string[] = [],
): ObjectPartialEqualityResult => {
  for (const [expectedKey, expectedValue] of Object.entries(expectedObject)) {
    if (!(expectedKey in actualObject)) {
      return {
        isPartiallyEqual: false,
        errorMessage: `Expected ${expectedKey} to be a property in ${JSON.stringify(actualObject)}`,
      };
    }

    objectKeyHistory.push(expectedKey);
    if (
      expectedValue instanceof Object &&
      actualObject[expectedKey] instanceof Object
    ) {
      const isEqual = comparePartialEqualityBetweenObjects(
        actualObject[expectedKey],
        expectedValue,
        objectKeyHistory,
      );

      if (!isEqual.isPartiallyEqual) {
        return isEqual;
      }
      objectKeyHistory.pop();
      continue;
    }

    const actualValue = actualObject[expectedKey];
    if (
      typeof expectedValue === "string" &&
      TYPE_CHECK_REGEX.test(expectedValue)
    ) {
      const validationRes = validateValueType(
        expectedValue,
        actualValue,
        objectKeyHistory,
      );

      if (!validationRes.isPartiallyEqual) {
        return validationRes;
      }

      objectKeyHistory.pop();
      continue;
    }

    if (expectedValue !== actualValue) {
      return {
        isPartiallyEqual: false,
        errorMessage: `Expected "${expectedValue}" for field ${formatKeyHistory(objectKeyHistory)} but got "${actualValue}"`,
      };
    }
    objectKeyHistory.pop();
  }
  return { isPartiallyEqual: true };
};

const validateValueType = (
  expectedType: string,
  actualValue: any,
  keyHistory: string[],
): ObjectPartialEqualityResult => {
  const typeMatch = expectedType.match(TYPE_CHECK_REGEX);
  if (!typeMatch) {
    throw new Error(`${expectedType} is unsupported.`);
  }

  const type = typeMatch[1].toLowerCase();
  if (type in SupportedTypeMatchers) {
    return typeof actualValue === type
      ? { isPartiallyEqual: true }
      : {
          isPartiallyEqual: false,
          errorMessage: `Expected ${formatKeyHistory(keyHistory)} to be type ${type} but it was type ${typeof actualValue}`,
        };
  } else {
    throw new Error(`${expectedType} is unsupported.`);
  }
};

const formatKeyHistory = (keyHistory: string[]): string => {
  const formattedKeyHistory: string[] = [keyHistory[0]];
  for (let i = 1; i < keyHistory.length; i++) {
    const key = keyHistory[i];
    if (isNumeric(key)) {
      formattedKeyHistory.push(`[${key}]`);
      continue;
    }
    formattedKeyHistory.push(`.${key}`);
  }
  return formattedKeyHistory.join("");
};

const isNumeric = (target: string): boolean => !isNaN(parseInt(target));
