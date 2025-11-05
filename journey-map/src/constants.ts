export const JOURNEY_TYPES: Record<string, string> = {
  INITIAL_JOURNEY_SELECTION: "Initial journey selection",
  NEW_P1_IDENTITY: "New P1 identity",
  NEW_P2_IDENTITY: "New P2 identity",
  REUSE_EXISTING_IDENTITY: "Reuse existing identity",
  UPDATE_NAME: "Update name",
  UPDATE_ADDRESS: "Update address",
  INELIGIBLE: "Ineligible journey",
  FAILED: "Failed journey",
  TECHNICAL_ERROR: "Technical error",
  REPEAT_FRAUD_CHECK: "Repeat fraud check",
  SESSION_TIMEOUT: "Session timeout",
  F2F_HAND_OFF: "F2F hand off",
  F2F_PENDING: "F2F pending",
  F2F_FAILED: "F2F failed",
  REVERIFICATION: "Reverification",
};

export const NESTED_JOURNEY_TYPES: Record<string, string> = {
  ADDRESS_AND_FRAUD: "Address and fraud",
  APP_DOC_CHECK: "App doc check",
  KBVS: "KBVs",
  STRATEGIC_APP_HANDLE_RESULT: "Strategic app handle result",
  STRATEGIC_APP_TRIAGE: "Strategic app triage",
  WEB_DL_OR_PASSPORT: "Web DL or passport",
};

// These are the sub-journeys which a user starts on before going through any other sub-journey
export const FIRST_JOURNEYS: string[] = [
  "INITIAL_JOURNEY_SELECTION",
  "REVERIFICATION",
];

export const COMMON_JOURNEY_TYPES: string[] = [
  "NEW_P1_IDENTITY",
  "NEW_P2_IDENTITY",
  "REUSE_EXISTING_IDENTITY",
  "REPEAT_FRAUD_CHECK",
  "REVERIFICATION",
  "UPDATE_ADDRESS",
  "UPDATE_NAME",
];

export const CRI_NAMES: Record<string, string> = {
  address: "Address",
  claimedIdentity: "Claimed Identity",
  bav: "Bank account",
  dcmaw: "DCMAW (app)",
  dcmawAsync: "DCMAW ASYNC (app)",
  drivingLicence: "Driving licence (web)",
  dwpKbv: "DWP KBV",
  f2f: "Face-to-face",
  fraud: "Experian fraud",
  experianKbv: "Experian KBV",
  nino: "HMRC check (NINO)",
  ukPassport: "Passport (web)",
  ticf: "TICF",
};

export const TOP_DOWN_JOURNEYS = ["INITIAL_JOURNEY_SELECTION"];
export const ERROR_JOURNEYS = ["TECHNICAL_ERROR"];
export const FAILURE_JOURNEYS = ["INELIGIBLE", "FAILED"];
