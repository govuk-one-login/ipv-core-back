import { logger } from "./logger";

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_BASE_BACKOFF_MILLIS = 50;

const wait = async (millis: number): Promise<void> => {
  return new Promise((resolve) => setTimeout(resolve, millis));
};

// Retry an optional task with exponential backoff until it returns a value
// or exceeds the maximum number of retries
export const retryOptionalTask = async <T extends object>(
  task: () => Promise<T | undefined>,
  maxAttempts: number = DEFAULT_MAX_ATTEMPTS,
  baseDelay: number = DEFAULT_BASE_BACKOFF_MILLIS,
): Promise<T | undefined> => {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const result = await task();

    if (result !== undefined) {
      return result;
    }

    if (attempt < maxAttempts) {
      logger.info("Retrying task...");
      await wait(baseDelay * Math.pow(2, attempt - 1));
    }
  }
  return undefined;
};
