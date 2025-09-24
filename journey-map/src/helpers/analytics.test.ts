import { describe, it } from "node:test";
import assert from "node:assert";
import { parseTransitionsApiForm } from "./analytics.js";

describe("parseTransitionsApiSettings", () => {
  const createFormData = (entries: Record<string, string>): FormData => {
    const formData = new FormData();
    for (const [key, value] of Object.entries(entries)) {
      formData.set(key, value);
    }
    return formData;
  };

  const originalGetTz = Date.prototype.getTimezoneOffset;
  const setTzOffset = (minutes: number): void => {
    Date.prototype.getTimezoneOffset = () => {
      return minutes;
    };
  };
  const restoreTzOffset = (): void => {
    Date.prototype.getTimezoneOffset = originalGetTz;
  };

  it("should correctly parse settings when session id is present", () => {
    setTzOffset(-120); // UTC +02:00
    try {
      const formData = createFormData({
        fromDate: "2025-09-16T10:00",
        toDate: "2025-09-16T12:00",
        sessionJourneySelection: "session",
        journeySession: "test-session-id",
        targetEnvironment: "production",
      });

      const result = parseTransitionsApiForm(formData);

      assert.equal(result.fromDate, "2025-09-16T10:00+02:00");
      assert.equal(result.toDate, "2025-09-16T12:00+02:00");
      assert.equal(result.ipvSessionId, "test-session-id");
      assert.equal(result.environment, "production");
      assert.ok(!("govukJourneyId" in result));
    } finally {
      restoreTzOffset();
    }
  });

  it("should correctly parse settings when journey id is present", () => {
    try {
      // Arrange
      setTzOffset(-120); // UTC +02:00
      const formData = createFormData({
        fromDate: "2025-09-16T10:00",
        toDate: "2025-09-16T12:00",
        sessionJourneySelection: "journey",
        journeySession: "test-session-id",
        targetEnvironment: "production",
      });

      // Act
      const result = parseTransitionsApiForm(formData);

      // Assert
      assert.equal(result.fromDate, "2025-09-16T10:00+02:00");
      assert.equal(result.toDate, "2025-09-16T12:00+02:00");
      assert.equal(result.govukJourneyId, "test-session-id");
      assert.equal(result.environment, "production");
      assert.ok(!("ipvSessionId" in result));
    } finally {
      restoreTzOffset();
    }
  });

  it("should correctly parse settings when session/journey id is not provided", () => {
    try {
      // Arrange
      setTzOffset(-120); // UTC +02:00
      const formData = createFormData({
        fromDate: "2025-09-16T10:00",
        toDate: "2025-09-16T12:00",
        sessionJourneySelection: "journey",
        targetEnvironment: "production",
      });

      // Act
      const result = parseTransitionsApiForm(formData);

      // Assert
      assert.equal(result.fromDate, "2025-09-16T10:00+02:00");
      assert.equal(result.toDate, "2025-09-16T12:00+02:00");
      assert.equal(result.environment, "production");
      assert.ok(!("ipvSessionId" in result));
      assert.ok(!("govukJourneyId" in result));
    } finally {
      restoreTzOffset();
    }
  });
});
