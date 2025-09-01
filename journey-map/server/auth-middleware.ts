import { RequestHandler } from "express";

const AUTHORIZATION_TYPE = "Basic";

const isAuthorised = (authHeader: string) => {
  const encodedHeader = authHeader
    .substring(AUTHORIZATION_TYPE.length + 1)
    .trim();
  const [username, password] = atob(encodedHeader).split(":");

  return (
    username === process.env.JOURNEY_MAP_USERNAME &&
    password === process.env.JOURNEY_MAP_PASSWORD
  );
};

export const authorise: RequestHandler = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !isAuthorised(authHeader)) {
    res.header("WWW-Authenticate", AUTHORIZATION_TYPE);
    res.status(401).send("Unauthorized");
    return;
  }

  next();
};
