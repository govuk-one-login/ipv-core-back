import express from 'express';

const PORT = 3000;

const app = express();
app.use(express.static('public'));
app.use(express.static('../lambdas/process-journey-event/src/main/resources/statemachine/journey-maps/'));

app.listen(PORT, () => {
    console.log(`Diagram available at http://localhost:${PORT}`);
});
