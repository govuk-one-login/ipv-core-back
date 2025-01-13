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

export const compareAuditEvents = (
  actualAuditEvents: AuditEvent[],
  expectedAuditEvent: AuditEvent[],
): ObjectPartialEqualityResult => {
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
