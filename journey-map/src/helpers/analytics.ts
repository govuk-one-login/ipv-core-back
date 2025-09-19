import { TransitionsApiRequestBody } from "../service/analyticsService.js";

const addSystemTimeZone = (dateTimeStr: string): string => {
  const date = new Date(dateTimeStr);
  const offset = date.getTimezoneOffset();
  const sign = offset > 0 ? "-" : "+";
  const absOffset = Math.abs(offset);
  const offsetHours = String(Math.floor(absOffset / 60)).padStart(2, "0");
  const offsetMinutes = String(absOffset % 60).padStart(2, "0");
  return `${dateTimeStr}${sign}${offsetHours}:${offsetMinutes}`;
};

export const parseTransitionsApiForm = (
  formData: FormData,
): TransitionsApiRequestBody => {
  const selection = formData.get("sessionJourneySelection") as string;
  const typedInput = (formData.get("journeySession") as string) ?? "";

  return {
    fromDate: addSystemTimeZone(formData.get("fromDate") as string),
    toDate: addSystemTimeZone(formData.get("toDate") as string),
    ...(selection === "session" && typedInput
      ? { ipvSessionId: typedInput }
      : {}),
    ...(selection === "journey" && typedInput
      ? { govukJourneyId: typedInput }
      : {}),
    environment: formData.get("targetEnvironment") as string,
  };
};
