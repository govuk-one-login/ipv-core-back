import express from "express";
import { authorise } from "./auth-middleware.js";

const port = process.env.PORT || 3000;
const isDevelopment = process.env.NODE_ENV === "development";

const app = express();

if (!isDevelopment) {
  app.use(authorise);
}

app.use(express.static("public"));
app.use(express.static("journey-maps"));

app.get("/healthcheck", (req, res) => {
  res.status(200).send("OK");
});

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
