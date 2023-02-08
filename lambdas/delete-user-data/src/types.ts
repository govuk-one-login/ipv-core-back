export type Message = { user_id: string };

export type VCItemKey = {
  userId: string;
  credentialIssuer: string;
};

export type AuditUser = {
  user_id?: string;
  govuk_signin_journey_id?: string;
  ip_address?: string;
};

export type AuditEvent = {
  timestamp: number; // Epoch seconds
  component_id: string;
  event_name: string;
  user: AuditUser;
  extensions?: unknown;
};
