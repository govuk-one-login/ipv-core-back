export interface AuditEvent {
  event_name: string;
  event_timestamp_ms: number;
  component_id: string;
  user: {
    user_id: string;
    session_id: string;
    govuk_signin_journey_id: string;
    ip_address: string;
  };
  extensions?: unknown;
  restricted?: unknown;
}
