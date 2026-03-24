import path from "path";
import { fileURLToPath } from "url";
import fs from "node:fs/promises";
import { AuditEvent } from "../types/audit-events.js";
import {
  comparePartialEqualityBetweenObjects,
  ObjectPartialEqualityResult,
} from "./object-matchers.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const getAuditEventsForJourneyType = async (journeyName: string) => {
  return JSON.parse(
    await fs.readFile(
      path.join(__dirname, `../../data/audit-events/${journeyName}.json`),
      "utf8",
    ),
  ) as AuditEvent[];
};

const diffAuditEventNames = (
  actualEvents: AuditEvent[],
  expectedEvents: AuditEvent[],
): string => {
  const actualNames = actualEvents.map((e) => e.event_name);
  const expectedNames = expectedEvents.map((e) => e.event_name);
  const missingFromActual = expectedNames.filter(
    (n) => !actualNames.includes(n),
  );
  const unexpectedInActual = actualNames.filter(
    (n) => !expectedNames.includes(n),
  );
  return [
    missingFromActual.length ? `Missing: [${missingFromActual}]` : "",
    unexpectedInActual.length ? `Unexpected: [${unexpectedInActual}]` : "",
  ]
    .filter(Boolean)
    .join(", ");
};

export const compareAuditEvents = (
  actualAuditEvents: AuditEvent[],
  expectedAuditEvent: AuditEvent[],
): ObjectPartialEqualityResult => {
  if (actualAuditEvents.length !== expectedAuditEvent.length) {
    return {
      isPartiallyEqual: false,
      errorMessage: `Expected (${expectedAuditEvent.length}) and actual (${actualAuditEvents.length}) events are not the same length. ${diffAuditEventNames(actualAuditEvents, expectedAuditEvent)}`,
    };
  }

  for (let i = 0; i < expectedAuditEvent.length; i++) {
    const comparisonResult = comparePartialEqualityBetweenObjects(
      actualAuditEvents[i],
      expectedAuditEvent[i],
    );

    if (!comparisonResult.isPartiallyEqual) {
      return comparisonResult;
    }
  }

  return { isPartiallyEqual: true };
};
