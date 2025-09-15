import { RequestHandler } from "express";
import config from "./config.js";

const CACHE_TTL_MS = 60 * 1000;

let cache: {
  data: object;
  expiresAt: number;
} | null = null;

const checkIfTimeWindowIsInRange = (from: string, to: string): boolean => {
  const fromDate = new Date(from);
  const toDate = new Date(to);
  return (
    toDate.getTime() - fromDate.getTime() < Number(config.maximumTimeRangeMs)
  );
};

export const fetchJourneyTransitionsHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const now = Date.now();
    if (cache && cache.expiresAt > now) {
      // res.json(cache.data);
      // next();
      // return;
    }

    const { fromDate, toDate } = req.body;
    if (!checkIfTimeWindowIsInRange(fromDate, toDate)) {
      res.status(400).json({
        message: `Maximum time range for fetching transition is ${config.maximumTimeRangeMs} ms.`,
      });
      return;
    }

    const query = new URLSearchParams({
      fromDate: fromDate,
      toDate: toDate,
      limit: "200",
    });

    const response = await fetch(
      `${config.journeyTransitionsEndpoint}?${query.toString()}`,
      {
        method: "POST",
        headers: { "x-api-key": config.analyticsApiKey },
      },
    );
    if (!response.ok) {
      throw new Error(
        `Failed to fetch journey transitions from analytics API: ${response.statusText}`,
      );
    }

    const data = await response.json();
    cache = {
      data,
      expiresAt: now + CACHE_TTL_MS,
    };

    res.set("Cache-Control", "public, max-age=60");
    res.json(data);
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
    const response = await fetch(config.systemSettingsEndpoint, {
      method: "POST",
      headers: { "x-api-key": config.analyticsApiKey },
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
