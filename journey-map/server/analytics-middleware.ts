import { RequestHandler } from "express";
import config from "./config.js";

const createURLSearchParams = (body): URLSearchParams => {
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
    const [environment, ...options] = req.body;
    const query = createURLSearchParams(options);

    const endpoint = config.environment[environment].journeyTransitionsEndpoint;
    const apiKey = config.environment[environment].analyticsApiKey;

    const response = await fetch(
      endpoint + query ? `?${query.toString()}` : "",
      {
        method: "POST",
        headers: { "x-api-key": apiKey },
      },
    );

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
