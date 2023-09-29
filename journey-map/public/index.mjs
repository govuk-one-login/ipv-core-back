const initialStates = ['INITIAL_IPV_JOURNEY'];
const errorStates = ['ERROR'];
const failureStates = ['PYI_KBV_FAIL', 'PYI_NO_MATCH', 'PYI_ANOTHER_WAY'];

// Traverse the journey map to collect the available 'disabled' and 'featureFlag' options
export const getOptions = (journeyMap) => {
    const disabledOptions = ['none'];
    const featureFlagOptions = ['none'];

    Object.values(journeyMap).forEach((definition) => {
        const events = definition.events || definition.exitEvents || {};
        Object.values(events).forEach((def) => {
            if (def.checkIfDisabled) {
                Object.keys(def.checkIfDisabled).forEach((opt) => {
                    if (!disabledOptions.includes(opt)) {
                        disabledOptions.push(opt);
                    }
                });
            }
            if (def.checkFeatureFlag) {
                Object.keys(def.checkFeatureFlag).forEach((opt) => {
                    if (!featureFlagOptions.includes(opt)) {
                        featureFlagOptions.push(opt);
                    }
                });
            }
        });
    });

    return { disabledOptions, featureFlagOptions };
}

// Expand out parent states
const expandParents = (journeyMap) => {
    const parentStates = [];
    Object.entries(journeyMap).forEach(([state, definition]) => {
        if (definition.parent) {
            const parent = journeyMap[definition.parent];
            definition.events = {
                ...parent.events,
                ...definition.events,
            };
            journeyMap[state] = { ...parent, ...definition };
            parentStates.push(definition.parent);
        }
    });
    parentStates.forEach((state) => delete journeyMap[state]);
};

// Expand out nested states
const expandNestedJourneys = (journeyMap, subjourneys) => {
    Object.entries(journeyMap).forEach(([state, definition]) => {
        if (definition.nestedJourney && subjourneys[definition.nestedJourney]) {
            delete journeyMap[state];
            const subjourney = subjourneys[definition.nestedJourney];

            // Expand out each of the nested states
            Object.entries(subjourney.nestedJourneyStates).forEach(([nestedState, nestedDefinition]) => {
                // Copy to avoid mutating different versions of the expanded definition
                const expandedDefinition = JSON.parse(JSON.stringify(nestedDefinition));

                Object.entries(expandedDefinition.events).forEach(([evt, def]) => {
                    // Map target states to expanded states
                    if (def.targetState) {
                        def.targetState = `${def.targetState}_${state}`;
                    }

                    // Map exit events to targets in the parent definition
                    if (def.exitEventToEmit) {
                        if (definition.exitEvents[def.exitEventToEmit]) {
                        def.targetState = definition.exitEvents[def.exitEventToEmit].targetState;
                        } else {
                            console.warn(`Unhandled exit event from ${state}:`, def.exitEventToEmit)
                            delete expandedDefinition.events[evt];
                        }
                        delete def.exitEventToEmit;
                    }
                });

                journeyMap[`${nestedState}_${state}`] = expandedDefinition;
            });

            // Update entry events on other states to expanded states
            Object.entries(subjourney.entryEvents).forEach(([entryEvent, def]) => {
                Object.values(journeyMap).forEach((journeyDef) => {
                    if (journeyDef.events?.[entryEvent]?.targetState === state) {
                        journeyDef.events[entryEvent].targetState = `${def.targetState}_${state}`;
                    }
                });
            });
        }
    });
};

// Should match logic in BasicEvent.java
const resolveEventTarget = (definition, options) => {
    if (definition.checkIfDisabled && definition.checkIfDisabled[options.disabled]) {
        return definition.checkIfDisabled[options.disabled].targetState;
    }
    if (definition.checkFeatureFlag && definition.checkFeatureFlag[options.featureFlag]) {
        return definition.checkFeatureFlag[options.featureFlag].targetState;
    }
    return definition.targetState;
}

// Render the transitions into mermaid, while tracking the states traced from the initial states
// This allows us to skip 
const renderTransitions = (journeyMap, options) => {
    const states = [...initialStates];
    const stateTransitions = [];

    for (let i = 0; i < states.length; i++) {
        const state = states[i];
        const definition = journeyMap[state];
        const events = definition.events || definition.exitEvents || {};

        const eventsByTarget = {};
        Object.entries(events).forEach(([eventName, def]) => {
            const target = resolveEventTarget(def, options);

            if (errorStates.includes(target) && !options.includeErrors) {
                return;
            }
            if (failureStates.includes(target) && !options.includeFailures) {
                return;
            }

            if (!states.includes(target)) {
                states.push(target);
            }
            eventsByTarget[target] = eventsByTarget[target] || [];
            eventsByTarget[target].push(eventName);
        });

        Object.entries(eventsByTarget).forEach(([target, eventNames]) => {
            stateTransitions.push(`    ${state}-->|${eventNames.join('\\n')}|${target}`);
        });
    }

    return { transitionsMermaid: stateTransitions.join('\n'), states };
};

const renderStates = (journeyMap, states) => {
    // Types
    // process - response.type = process, response.lambda = <lambda>
    // page    - response.type = page, response.pageId = 'page-id'
    // cri     - response.type = cri, 
    const mermaids = states.map((state) => {
        const definition = journeyMap[state];

        switch (definition.response?.type) {
            case 'process':
                return `    ${state}(${state}\\n${definition.response.lambda}):::process`;
            case 'page':
                return failureStates.includes(state)
                    ? `    ${state}[${state}\\n${definition.response.pageId}]:::error_page`
                    : `    ${state}[${state}\\n${definition.response.pageId}]:::page`;
            case 'cri':
                return `    ${state}([${state}\\n${definition.response.criId}]):::cri`;
            case 'error':
                return `    ${state}:::error_page`
            default:
                return `    ${state}`;
        }
    });

    return { statesMermaid: mermaids.join('\n') };
};

export const render = (journeyMap, nestedJourneys, options = {}) => {
    // Copy to avoid mutating the input
    const journeyMapCopy = JSON.parse(JSON.stringify(journeyMap));
    if (options.expandNestedJourneys) {
        expandNestedJourneys(journeyMapCopy, nestedJourneys);
    }
    expandParents(journeyMapCopy);

    const { transitionsMermaid, states } = renderTransitions(journeyMapCopy, options);
    const { statesMermaid } = renderStates(journeyMapCopy, states);

    const mermaid =
`graph LR
    classDef process fill:#ffa,stroke:#330;
    classDef page fill:#ae8,stroke:#050;
    classDef error_page fill:#f99,stroke:#500;
    classDef cri fill:#faf,stroke:#303;
${statesMermaid}
${transitionsMermaid}
`;

    return mermaid;
};
