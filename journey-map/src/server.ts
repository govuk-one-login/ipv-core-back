import basicAuth from "express-basic-auth";
import express from "express";

const port = process.env.PORT || 3000;
const isDevelopment = process.env.NODE_ENV === "development";

const app = express();

app.get("/healthcheck", (req, res) => {
  res.status(200).send("OK");
});

// In deployed environments we apply basic auth
if (!isDevelopment) {
  app.use(basicAuth({
    users: {
      ipvcore: "ipvcore",
    },
    challenge: true,
  }));
}

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
