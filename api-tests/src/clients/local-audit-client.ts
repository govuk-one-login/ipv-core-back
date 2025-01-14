import config from "../config/config.js";
import { AuditEvent } from "../types/audit-events.js";

export const getAuditEvents = async (userId: string): Promise<AuditEvent[]> => {
  const response = await fetch(
    `${config.core.externalApiUrl}/audit-events?${new URLSearchParams({
      user_id: userId,
    }).toString()}`,
  );

  if (!response.ok) {
    throw new Error(
      `getAuditEventsForUser request failed: ${response.statusText}`,
    );
  }

  return (await response.json()) as AuditEvent[];
};
