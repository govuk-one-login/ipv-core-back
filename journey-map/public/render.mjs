const topDownJourneys = ['INITIAL_JOURNEY_SELECTION'];
const errorJourneys = ['TECHNICAL_ERROR'];
const failureJourneys = ['INELIGIBLE', 'FAILED'];

const EXIT_NESTED_JOURNEY_MAP_STATE = "EXIT";
const ENTRY_NESTED_JOURNEY_MAP_STATE = "ENTRY";

const addDefinitionOptions = (definition, disabledOptions, featureFlagOptions) => {
    Object.entries(definition.checkIfDisabled || {}).forEach(([opt, def]) => {
        if (!disabledOptions.includes(opt)) {
            disabledOptions.push(opt);
        }
        addDefinitionOptions(def, disabledOptions, featureFlagOptions);
    });
    Object.entries(definition.checkFeatureFlag || {}).forEach(([opt, def]) => {
        if (!featureFlagOptions.includes(opt)) {
            featureFlagOptions.push(opt);
        }
        addDefinitionOptions(def, disabledOptions, featureFlagOptions);
    });
};

// Traverse the journey map to collect the available 'disabled' and 'featureFlag' options
export const getOptions = (journeyMaps) => {
    const disabledOptions = [];
    const featureFlagOptions = [];

    Object.values(journeyMaps).forEach((journeyMap) => {
        Object.values(journeyMap.states).forEach((definition) => {
            const events = definition.events || definition.exitEvents || {};
            Object.values(events).forEach((def) => {
                addDefinitionOptions(def, disabledOptions, featureFlagOptions);
            });
        });
    });

    return { disabledOptions, featureFlagOptions };
};

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

// Should match logic in BasicEvent.java
const resolveEventTarget = (definition, formData) => {
    // Look for an override for disabled CRIs
    const disabledCris = formData.getAll('disabledCri');
    const disabledResolution = Object.keys(definition.checkIfDisabled || {}).find((k) => disabledCris.includes(k));
    if (disabledResolution) {
        return resolveEventTarget(definition.checkIfDisabled[disabledResolution], formData);
    }

    // Look for an override for feature flags
    const featureFlags = formData.getAll('featureFlag');
    const featureFlagResolution = Object.keys(definition.checkFeatureFlag || {}).find((k) => featureFlags.includes(k));
    if (featureFlagResolution) {
        return resolveEventTarget(definition.checkFeatureFlag[featureFlagResolution], formData);
    }

    return definition;
};

// Expand out nested states
const expandNestedJourneys = (journeyMap, subjourneys, formData) => {
    Object.entries(journeyMap).forEach(([state, definition]) => {
        if (definition.nestedJourney && subjourneys[definition.nestedJourney]) {
            delete journeyMap[state];
            const subjourney = subjourneys[definition.nestedJourney];

            // Expand out each of the nested states
            Object.entries(subjourney.nestedJourneyStates).forEach(([nestedState, nestedDefinition]) => {
                // Copy to avoid mutating different versions of the expanded definition
                const expandedDefinition = JSON.parse(JSON.stringify(nestedDefinition));

                Object.entries(expandedDefinition.events || {}).forEach(([evt, def]) => {
                    // Map target states to expanded states
                    if (def.targetState && !def.targetJourney) {
                        def.targetState = `${def.targetState}_${state}`;
                    }

                    // Map exit events to targets in the parent definition
                    if (def.exitEventToEmit) {
                        if (definition.exitEvents[def.exitEventToEmit]) {
                            Object.assign(def, definition.exitEvents[def.exitEventToEmit]);
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
                    if (journeyDef.events?.[entryEvent]) {
                        const target = resolveEventTarget(journeyDef.events[entryEvent], formData);
                        if (target.targetState === state) {
                            target.targetState = `${def.targetState}_${state}`
                        }
                    }
                });
            });
        }
    });
};

// Render the transitions into mermaid, while tracking the states traced from the initial states
// This allows us to skip
const renderTransitions = (journeyStates, formData) => {
    const states = Object.keys(journeyStates)
            .filter((s) => !journeyStates[s].response && !journeyStates[s].nestedJourney);
    const stateTransitions = [];

    for (let i = 0; i < states.length; i++) {
        const state = states[i];
        const definition = journeyStates[state];
        const events = definition.events || definition.exitEvents || {};

        const eventsByTarget = {};
        Object.entries(events).forEach(([eventName, def]) => {
            const { targetJourney, targetState, exitEventToEmit } = resolveEventTarget(def, formData);

            let target;
            if (exitEventToEmit) {
                // An exitEventToEmit is only present in nested journeys. Events wth this target always end at
                // the EXIT state in the nested journey map
                target = `${exitEventToEmit}_exit-event`;
            } else {
                target = targetJourney ? `${targetJourney}__${targetState}` : targetState;
            }

            if (errorJourneys.includes(targetJourney) &&
                !formData.getAll('otherOption').includes('includeErrors')) {
                return;
            }
            if (failureJourneys.includes(targetJourney) &&
                !formData.getAll('otherOption').includes('includeFailures')) {
                return;
            }

            if (!states.includes(target)) {
                states.push(target);
            }

            eventsByTarget[target] = eventsByTarget[target] || [];
            eventsByTarget[target].push(eventName);

            if (!journeyStates[target]) {
                if (targetJourney) {
                    journeyStates[target] = {
                        response: {
                            type: 'journeyTransition',
                            targetJourney,
                            targetState,
                        }
                    };
                } else if (exitEventToEmit) {
                    journeyStates[`${exitEventToEmit}_exit-event`] = {}
                } else {
                    throw new Error(`Failed to resolve state ${target} from ${state}`);
                }
            }
        });

        Object.entries(eventsByTarget).forEach(([target, eventNames]) => {
            stateTransitions.push(`    ${state}-->|${eventNames.join('\\n')}|${target}`);
        });
    }

    return { transitionsMermaid: stateTransitions.join('\n'), states };
};

const renderClickHandler = (state, definition) => {
    if (definition.nestedJourney) {
        definition.response = {
            type: "nestedJourney",
            ...definition
        }
    }
    // Click handler serializes the definition to Base64-encoded JSON to avoid escaping issues
    return `    click ${state} call onStateClick(${JSON.stringify(state)}, ${btoa(JSON.stringify( definition.response ?? {}))})`;
};

const renderState = (state, definition) => {
    // Types
    // process - response.type = process, response.lambda = <lambda>
    // page    - response.type = page, response.pageId = 'page-id'
    // cri     - response.type = cri,
    if (definition.nestedJourney) {
        return `    ${state}(${state}):::nested_journey`;
    }

    switch (definition.response?.type) {
        case 'process':
            return `    ${state}(${state}\\n${definition.response.lambda}):::process`;
        case 'page':
        case 'error':
            return `    ${state}[${state}\\n${definition.response.pageId}]:::page`;
        case 'cri':
            const contextInfo = definition.response.context ? `\\n context: ${definition.response.context}` : "";
            const scopeInfo = definition.response.scope ? `\\n scope: ${definition.response.scope}` : "";
            return `    ${state}([${state}\\n${definition.response.criId}${contextInfo}${scopeInfo}]):::cri`;
        case 'journeyTransition':
            const { targetJourney, targetState } = definition.response;
            return (failureJourneys.includes(targetJourney) || errorJourneys.includes(targetJourney))
                ? `    ${state}(${targetJourney}\\n${targetState}):::error_transition`
                : `    ${state}(${targetJourney}\\n${targetState}):::journey_transition`;
        default:
            return `    ${state}:::other`;
    }
};

const renderStates = (journeyMapStates, states) => {
    const mermaids = states.flatMap((state) => {
        const definition = journeyMapStates[state];

        return [
            renderState(state, definition),
            renderClickHandler(state, definition),
        ];
    });

    return { statesMermaid: mermaids.join('\n') };
};

const resolveAllPossibleEventTargets = (eventDefinition) => [
    eventDefinition.targetState,
    ...Object.values(eventDefinition.checkIfDisabled || {}).flatMap(resolveAllPossibleEventTargets),
    ...Object.values(eventDefinition.checkFeatureFlag || {}).flatMap(resolveAllPossibleEventTargets)
];

const calcOrphanStates = (journeyMap) => {
    const targetedStates = [
        ...Object.values(journeyMap).flatMap((stateDefinition) => [
            ...Object.values(stateDefinition.events || {}).flatMap(resolveAllPossibleEventTargets),
            ...Object.values(stateDefinition.exitEvents || {}).flatMap(resolveAllPossibleEventTargets)
        ])
    ]

    const uniqueTargetedStates = [...new Set(targetedStates)];

    return Object.keys(journeyMap).filter(state => !uniqueTargetedStates.includes(state));
};

const getNestedJourneyStatesFlatMap = nestedJourney => ({
    ...nestedJourney.nestedJourneyStates,
    // map entryEvents to an `ENTRY` state - this acts as the starting block of a nested journey map
    [ENTRY_NESTED_JOURNEY_MAP_STATE]: {
        events: nestedJourney.entryEvents
    }
})

const getMermaidGraph = (graphDirection, statesMermaid, transitionsMermaid) =>
    // These styles should be kept in sync with the key in style.css
            `graph ${graphDirection}
                classDef process fill:#ffa,stroke:#000;
                classDef page fill:#ae8,stroke:#000;
                classDef cri fill:#faf,stroke:#000;
                classDef journey_transition fill:#aaf,stroke:#000;
                classDef error_transition fill:#f99,stroke:#000;
                classDef other fill:#f3f2f1,stroke:#000;
                classDef nested_journey fill:#aaedff,stroke:#000;
            ${statesMermaid}
            ${transitionsMermaid}
            `;

export const render = (selectedJourney, journeyMaps, nestedJourneys, formData = new FormData()) => {
    const isNestedJourney = selectedJourney in nestedJourneys;
    let journeyMapCopy;

    const direction = topDownJourneys.includes(selectedJourney) ? 'TD' : 'LR';

    if (isNestedJourney) {
        // Copy to avoid mutating the input
        journeyMapCopy = JSON.parse(JSON.stringify(nestedJourneys[selectedJourney]));

        const nestedJourneyStates = getNestedJourneyStatesFlatMap(journeyMapCopy);

        const { transitionsMermaid, states } = renderTransitions(nestedJourneyStates, formData);
        const { statesMermaid } = renderStates(nestedJourneyStates, states);

        return getMermaidGraph(direction, statesMermaid, transitionsMermaid);
    } else {
        // Copy to avoid mutating the input
        journeyMapCopy = JSON.parse(JSON.stringify(journeyMaps[selectedJourney]));

        if (formData.getAll('otherOption').includes('expandNestedJourneys')) {
            expandNestedJourneys(journeyMapCopy.states, nestedJourneys, formData);
        }

        expandParents(journeyMapCopy.states);

        const { transitionsMermaid, states } = formData.getAll('otherOption').includes('onlyOrphanStates')
            ? { transitionsMermaid: '', states: calcOrphanStates(journeyMapCopy.states) }
            : renderTransitions(journeyMapCopy.states, formData);

        const { statesMermaid } = renderStates(journeyMapCopy.states, states);

        return getMermaidGraph(direction, statesMermaid, transitionsMermaid);
    }
};
