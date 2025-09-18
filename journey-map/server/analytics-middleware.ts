import { RequestHandler } from "express";
import config from "./config.js";

const CACHE_TTL_MS = 60 * 1000;

let cache: {
  data: object;
  expiresAt: number;
} | null = null;

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

    const filteredBody = Object.fromEntries(
      Object.entries(req.body).filter(([key]) => key !== "environment"),
    );

    const query = new URLSearchParams({
      ...filteredBody,
      limit: "200",
    });

    const targetEnvironment = req.body
      .environment as keyof typeof config.environment;
    const endpoint =
      config.environment[targetEnvironment].journeyTransitionsEndpoint;
    const apiKey = config.environment[targetEnvironment].analyticsApiKey;

    const response = await fetch(`${endpoint}?${query.toString()}`, {
      method: "POST",
      headers: { "x-api-key": apiKey },
    });

    const data = await response.json();

    switch (response.status) {
      case 200:
        cache = {
          data,
          expiresAt: now + CACHE_TTL_MS,
        };
        res.set("Cache-Control", "public, max-age=60");
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
