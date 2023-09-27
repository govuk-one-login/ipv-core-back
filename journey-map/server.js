import express from 'express';
import fs from 'fs/promises';
import yaml from 'yaml';

const PORT = 3000;
const JOURNEY_MAP_PATH = '../lambdas/process-journey-event/src/main/resources/statemachine/journey-maps/ipv-core-main-journey.yaml';

const app = express();

app.use(express.static('assets'));

app.get('/journeymap.json', async (req, res) => {
    const file = await fs.readFile(JOURNEY_MAP_PATH, 'utf-8');
    const journeyMap = yaml.parse(file);

    // Expand out parent states for ease of consumption
    const parentStates = [];
    Object.entries(journeyMap).forEach(([state, definition]) => {
        if (definition.parent) {
            journeyMap[state] = { ...journeyMap[definition.parent], ...definition };
            parentStates.push(definition.parent);
        }
    });
    parentStates.forEach((state) => delete journeyMap[state]);

    res.json(journeyMap);
});

app.listen(PORT, () => {
    console.log(`Diagram available at http://localhost:${PORT}`);
});
