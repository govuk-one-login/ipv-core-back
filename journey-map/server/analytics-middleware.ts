import { RequestHandler } from "express";
import config from "./config.js";

interface JourneyTransitionsRequestBody {
  fromDate: string;
  toDate: string;
  govukJourneyId?: string;
  ipvSessionId?: string;
  environment: string;
}

const createURLSearchParams = (
  body: JourneyTransitionsRequestBody,
): URLSearchParams => {
  const query = new URLSearchParams({
    fromDate: body.fromDate,
    toDate: body.toDate,
  });
  if (body.govukJourneyId) {
    query.set("govukJourneyId", body.govukJourneyId);
  }

  if (body.ipvSessionId) {
    query.set("ipvSessionId", body.ipvSessionId);
  }
  return query;
};

export const fetchJourneyTransitionsHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const { fromDate, toDate } = req.body;
    const to = new Date(toDate).getTime();
    const from = new Date(fromDate).getTime();
    const maximumTimeRange = config.maximumTimeRangeMs as number;
    if (to - from > maximumTimeRange) {
      res.status(400).json({
        message: `Maximum time window is ${maximumTimeRange / 1000 / 60 / 60 / 24} days.`,
      });
      next();
      return;
    }

    const { environment, ...options } = req.body;
    const env = environment as keyof typeof config.environment;
    const query = createURLSearchParams(options);

    const endpoint = config.environment[env].journeyTransitionsEndpoint;
    const apiKey = config.environment[env].analyticsApiKey;
    const url = endpoint + (query ? `?${query.toString()}` : "");

    const response = await fetch(url, {
      method: "POST",
      headers: { "x-api-key": apiKey },
    });

    const data = await response.json();

    if (response.status === 200) {
      res.json(data);
    } else {
      console.error(
        "Error fetching journey counts, analytics response: ",
        response,
        data,
      );

      let errorMessage =
        "Error: Analytics endpoint responded with: " + response.status;
      if (data.code && userMessagesByTransitionFetchErrorCode[data.code]) {
        errorMessage = userMessagesByTransitionFetchErrorCode[data.code];
      } else if (data.message) {
        errorMessage =
          "Error: Analytics endpoint responded with: " + data.message;
      }

      res.status(500).json({
        message: errorMessage,
      });
    }
    next();
  } catch (err) {
    console.error("Error fetching counts: ", err);
    next(err);
  }
};

export const fetchSystemSettingsHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const environment = req.params.environment;
    const envConfig = config.environment[environment];

    const response = await fetch(envConfig.systemSettingsEndpoint, {
      method: "POST",
      headers: {
        "x-api-key": envConfig.analyticsApiKey,
      },
    });
    if (!response.ok) {
      throw new Error(
        `Failed to fetch system settings from analytics API: ${response.statusText}`,
      );
    }

    res.json(await response.json());
    next();
  } catch (err) {
    next(err);
  }
};

const userMessagesByTransitionFetchErrorCode: Record<number, string> = {
  0: "Unexpected error fetching user traffic",
  1: "Couldn't get user traffic from CloudWatch",
  2: "Timeout retrieving user traffic from CloudWatch. If this is the first time you have seen this error please try again, otherwise try reducing scope of your search to return fewer journeys.",
} as const;
