import config from "../config/config.js";
import { AuditEvent } from "../types/audit-events.js";

export const getAuditEvents = async (
  journeyId: string,
): Promise<AuditEvent[]> => {
  const response = await fetch(
    `${config.core.externalApiUrl}/audit-events?${new URLSearchParams({
      govuk_signin_journey_id: journeyId,
    }).toString()}`,
  );

  if (!response.ok) {
    throw new Error(`getAuditEvents request failed: ${response.statusText}`);
  }

  return (await response.json()) as AuditEvent[];
};
