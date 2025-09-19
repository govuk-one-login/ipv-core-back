import express from "express";
import { authorise } from "./auth-middleware.js";
import {
  fetchJourneyTransitionsHandler,
  fetchSystemSettingsHandler,
} from "./analytics-middleware.js";

const port = process.env.PORT || 3000;
const isDevelopment = process.env.NODE_ENV === "development";

const app = express();
app.use(express.json());

app.get("/healthcheck", (req, res) => {
  res.status(200).send("OK");
});

if (!isDevelopment) {
  app.use(authorise);
}

app.post("/journey-transitions", fetchJourneyTransitionsHandler);
app.get("/system-settings", fetchSystemSettingsHandler);

app.use(express.static("public"));
app.use(express.static("journey-maps"));

// In dev we load journey maps directly
if (isDevelopment) {
  app.use(
    express.static(
      "../lambdas/process-journey-event/src/main/resources/statemachine/journey-maps/",
    ),
  );
}

app.listen(port, () => {
  console.log(`Diagram available at http://localhost:${port}`);
});
