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

const countEventNames = (events: AuditEvent[]): Map<string, number> => {
  const counts = new Map<string, number>();
  for (const event of events) {
    counts.set(event.event_name, (counts.get(event.event_name) ?? 0) + 1);
  }
  return counts;
};

const diffAuditEventNames = (
  actualEvents: AuditEvent[],
  expectedEvents: AuditEvent[],
): string => {
  const actualCounts = countEventNames(actualEvents);
  const expectedCounts = countEventNames(expectedEvents);

  const differences: string[] = [];

  const allNames = new Set([...actualCounts.keys(), ...expectedCounts.keys()]);
  for (const name of allNames) {
    const actualCount = actualCounts.get(name) ?? 0;
    const expectedCount = expectedCounts.get(name) ?? 0;
    if (actualCount !== expectedCount) {
      differences.push(
        `${name}: expected ${expectedCount}, got ${actualCount}`,
      );
    }
  }

  return differences.length ? `Differences: [${differences.join("; ")}]` : "";
};

export const compareAuditEvents = (
  actualAuditEvents: AuditEvent[],
  expectedAuditEvent: AuditEvent[],
): ObjectPartialEqualityResult => {
  const eventNamesSummary = `\nExpected event names: [${expectedAuditEvent.map((e) => e.event_name).join(", ")}]\nActual event names: [${actualAuditEvents.map((e) => e.event_name).join(", ")}]`;

  if (actualAuditEvents.length !== expectedAuditEvent.length) {
    return {
      isPartiallyEqual: false,
      errorMessage: `Expected (${expectedAuditEvent.length}) and actual (${actualAuditEvents.length}) events are not the same length. ${diffAuditEventNames(actualAuditEvents, expectedAuditEvent)}.${eventNamesSummary}`,
    };
  }

  for (let i = 0; i < expectedAuditEvent.length; i++) {
    const comparisonResult = comparePartialEqualityBetweenObjects(
      actualAuditEvents[i],
      expectedAuditEvent[i],
    );

    if (!comparisonResult.isPartiallyEqual) {
      comparisonResult.errorMessage =
        comparisonResult.errorMessage + eventNamesSummary;
      return comparisonResult;
    }
  }

  return { isPartiallyEqual: true };
};
