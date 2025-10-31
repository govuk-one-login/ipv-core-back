import { describe, it, expect } from "vitest";
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

      expect(result.fromDate).toEqual("2025-09-16T10:00+02:00");
      expect(result.toDate).toEqual("2025-09-16T12:00+02:00");
      expect(result.ipvSessionId).toEqual("test-session-id");
      expect(result.environment).toEqual("production");
      expect(result).not.toContain("govukJourneyId");
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
      expect(result.fromDate).toEqual("2025-09-16T10:00+02:00");
      expect(result.toDate).toEqual("2025-09-16T12:00+02:00");
      expect(result.govukJourneyId).toEqual("test-session-id");
      expect(result.environment).toEqual("production");
      expect(result).not.toContain("ipvSessionId");
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
      expect(result.fromDate).toEqual("2025-09-16T10:00+02:00");
      expect(result.toDate).toEqual("2025-09-16T12:00+02:00");
      expect(result.environment).toEqual("production");
      expect(result).not.toContain("ipvSessionId");
      expect(result).not.toContain("govukJourneyId");
    } finally {
      restoreTzOffset();
    }
  });
});
