import config from "../config/config.js";
import { AuditEvent } from "../types/audit-events.js";

export const getAuditEvents = async (
  userId: string | undefined,
): Promise<AuditEvent[]> => {
  const queryString = userId
    ? `?${new URLSearchParams({ user_id: userId }).toString()}`
    : "";
  const apiUrl = `${config.core.externalApiUrl}/audit-events${queryString}`;
  const response = await fetch(apiUrl);

  if (!response.ok) {
    throw new Error(
      `getAuditEventsForUser request failed: ${response.statusText}`,
    );
  }

  return (await response.json()) as AuditEvent[];
};
