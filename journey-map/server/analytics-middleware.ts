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

    switch (response.status) {
      case 200:
        res.json(data);
        break;
      case 400:
        res.status(400).json({
          message: data.message || "Bad Request",
        });
        break;
      case 404:
        res.status(404).json({
          message: data.message || "Resource not found",
        });
        break;
      case 500:
        res.status(500).json({
          message: "Internal Server Error",
        });
        break;
      default:
        res.status(response.status).json({
          message: `Unexpected status: ${response.status}`,
        });
        break;
    }
    next();
  } catch (err) {
    next(err);
  }
};

export const fetchSystemSettingsHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const response = await fetch(
      config.environment["production"].systemSettingsEndpoint,
      {
        method: "POST",
        headers: {
          "x-api-key": config.environment["production"].analyticsApiKey,
        },
      },
    );
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
