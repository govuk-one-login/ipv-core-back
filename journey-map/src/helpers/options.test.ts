import { parseApiSettings } from "./options.js";
import { describe, it } from "node:test";
import assert from "node:assert";

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
        isEnabled: "enableTraffic",
        fromDate: "2025-09-16T10:00",
        toDate: "2025-09-16T12:00",
        sessionJourneySelection: "session",
        journeySession: "test-session-id",
        targetEnvironment: "production",
      });

      const result = parseApiSettings(formData);

      assert.equal(result.isEnabled, true);
      assert.equal(result.body.fromDate, "2025-09-16T10:00+02:00");
      assert.equal(result.body.toDate, "2025-09-16T12:00+02:00");
      assert.equal(result.body.ipvSessionId, "test-session-id");
      assert.equal(result.body.environment, "production");
      assert.ok(!("govukJourneyId" in result.body));
    } finally {
      restoreTzOffset();
    }
  });

  it("should correctly parse settings when journey id is present", () => {
    try {
      // Arrange
      setTzOffset(-120); // UTC +02:00
      const formData = createFormData({
        isEnabled: "enableTraffic",
        fromDate: "2025-09-16T10:00",
        toDate: "2025-09-16T12:00",
        sessionJourneySelection: "journey",
        journeySession: "test-session-id",
        targetEnvironment: "production",
      });

      // Act
      const result = parseApiSettings(formData);

      // Assert
      assert.equal(result.isEnabled, true);
      assert.equal(result.body.fromDate, "2025-09-16T10:00+02:00");
      assert.equal(result.body.toDate, "2025-09-16T12:00+02:00");
      assert.equal(result.body.govukJourneyId, "test-session-id");
      assert.equal(result.body.environment, "production");
      assert.ok(!("ipvSessionId" in result.body));
    } finally {
      restoreTzOffset();
    }
  });

  it("should correctly parse settings when session/journey id is not provided", () => {
    try {
      // Arrange
      setTzOffset(-120); // UTC +02:00
      const formData = createFormData({
        isEnabled: "enableTraffic",
        fromDate: "2025-09-16T10:00",
        toDate: "2025-09-16T12:00",
        sessionJourneySelection: "journey",
        targetEnvironment: "production",
      });

      // Act
      const result = parseApiSettings(formData);

      // Assert
      assert.equal(result.isEnabled, true);
      assert.equal(result.body.fromDate, "2025-09-16T10:00+02:00");
      assert.equal(result.body.toDate, "2025-09-16T12:00+02:00");
      assert.equal(result.body.environment, "production");
      assert.ok(!("ipvSessionId" in result.body));
      assert.ok(!("govukJourneyId" in result.body));
    } finally {
      restoreTzOffset();
    }
  });
});
