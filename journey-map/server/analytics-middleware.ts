import { RequestHandler } from "express";
import config from "./config";

export const fetchJourneyTransitionsHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const minutes = req.query?.["minutes"];
    const ipvSessionId = req.query?.["ipv_session_id"];
    const query = new URLSearchParams({
      minutes: String(minutes ?? "30"),
      ipvSessionId: ipvSessionId ? String(ipvSessionId) : undefined,
      limit: "200",
    });

    const response = await fetch(
      `${config.journeyTransitionsEndpoint}?${query.toString()}`,
      {
        method: "POST",
        headers: {
          "x-api-key": config.analyticsApiKey,
        },
      },
    );
    if (!response.ok) {
      throw new Error(
        `Failed to fetch journey transitions from analytics API: ${response.statusText}`,
      );
    }

    res.json(await response.json());
    next();
  } catch (err) {
    next(err);
  }
};
