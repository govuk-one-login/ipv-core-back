import {getNestedJourneyStates, resolveEventTargets} from "./helpers.mjs";

const topDownJourneys = ['INITIAL_JOURNEY_SELECTION'];
const errorJourneys = ['TECHNICAL_ERROR'];
const failureJourneys = ['INELIGIBLE', 'FAILED'];

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
export const getOptions = (journeyMaps, nestedJourneys) => {
    const disabledOptions = ['ticf'];
    const featureFlagOptions = [];

    const states = [
        ...Object.values(journeyMaps)
            .flatMap(journeyMap => Object.values(journeyMap.states)),
        ...Object.values(nestedJourneys)
            .flatMap(nestedJourney => Object.values(nestedJourney.nestedJourneyStates)),
    ];

    states.forEach((definition) => {
        const events = definition.events || definition.exitEvents || {};
        Object.values(events).forEach((def) => {
            addDefinitionOptions(def, disabledOptions, featureFlagOptions);
        });
    });

    Object.values(nestedJourneys).forEach(nestedJourney => {
        Object.values(nestedJourney.entryEvents).forEach((def) => {
            addDefinitionOptions(def, disabledOptions, featureFlagOptions);
        });
    });

    disabledOptions.sort();
    featureFlagOptions.sort();

    return { disabledOptions, featureFlagOptions };
};

// Expand out parent states
// Will also search 'otherStates' (e.g. for nested journeys)
const expandParents = (journeyStates, otherStates) => {
    const parentStates = [];
    Object.entries(journeyStates).forEach(([state, definition]) => {
        if (definition.parent) {
            const parent = journeyStates[definition.parent] ?? otherStates[definition.parent];
            if (!parent) {
                console.warn(`Missing parent ${definition.parent} of state ${state}`);
            } else {
                definition.events = {
                    ...parent.events,
                    ...definition.events,
                };
                journeyStates[state] = { ...parent, ...definition };
                parentStates.push(definition.parent);
            }
        }
    });
    parentStates.forEach((state) => delete journeyStates[state]);
};

const mapTargetStatesToExpandedStates = (eventDef, subJourneyState) => {
    // Map target states to expanded states
    if (eventDef.targetState && !eventDef.targetJourney) {
        eventDef.targetState = `${eventDef.targetState}_${subJourneyState}`;
    }

    if (eventDef.checkJourneyContext) {
        const journeyCtx = Object.keys(eventDef.checkJourneyContext)[0];
        return mapTargetStatesToExpandedStates(eventDef.checkJourneyContext[journeyCtx], subJourneyState);
    }
}

// Expand out nested states
const expandNestedJourneys = (journeyMap, subjourneys, formData) => {
    Object.entries(journeyMap).forEach(([state, definition]) => {
        if (definition.nestedJourney && subjourneys[definition.nestedJourney]) {
            const subJourneyState = state;
            delete journeyMap[subJourneyState];
            const subjourney = subjourneys[definition.nestedJourney];

            // Expand out each of the nested states
            Object.entries(subjourney.nestedJourneyStates).forEach(([nestedState, nestedDefinition]) => {
                // Copy to avoid mutating different versions of the expanded definition
                const expandedDefinition = JSON.parse(JSON.stringify(nestedDefinition));

                Object.entries(expandedDefinition.events || {}).forEach(([evt, eventDef]) => {
                    mapTargetStatesToExpandedStates(eventDef, subJourneyState);

                    // Map exit events to targets in the parent definition
                    const exitEvent = def.exitEventToEmit;
                    if (exitEvent) {
                        delete def.exitEventToEmit;
                        if (definition.exitEvents[exitEvent]) {
                            Object.assign(def, definition.exitEvents[exitEvent]);
                        } else {
                            console.warn(`Unhandled exit event from ${subJourneyState}:`, exitEvent)
                            delete expandedDefinition.events[evt];
                        }
                    }
                });

                journeyMap[`${nestedState}_${subJourneyState}`] = expandedDefinition;
            });

            // Make a copy of the event definition to avoid mutating the original
            const entryEvents = JSON.parse(JSON.stringify(subjourney.entryEvents));
            // Update entry events on other states to expanded states
            Object.entries(entryEvents).forEach(([entryEvent, entryEventDef]) => {
                mapTargetStatesToExpandedStates(entryEventDef, subJourneyState);
                Object.values(journeyMap).forEach((journeyDef) => {
                    if (journeyDef.events?.[entryEvent]) {
                        const targets = resolveEventTargets(journeyDef.events[entryEvent], undefined, formData);
                        targets.forEach(target => {
                            if (target.targetState === subJourneyState && !target.targetEntryEvent) {
                                journeyDef.events[entryEvent] = entryEventDef;
                            }
                        })
                    }
                    // Resolve targets with a `targetEntryEvent` override
                    Object.values(journeyDef.events ?? {}).forEach((eventDef) => {
                        const target = resolveEventTarget(eventDef, formData);
                        if (target.targetState === state && target.targetEntryEvent === entryEvent) {
                            target.targetState = `${def.targetState}_${state}`;
                            delete target.targetEntryEvent;
                        }
                    });
                });
            });
        }
    });
};

// Render the transitions into mermaid, while tracking the states traced from the initial states
// This allows us to skip
const renderTransitions = (journeyStates, formData) => {
    // Initial states have no response or nested journey
    const initialStates = Object.keys(journeyStates)
            .filter((s) => !journeyStates[s].response && !journeyStates[s].nestedJourney);

    const states = [...initialStates];
    const stateTransitions = [];

    for (let i = 0; i < states.length; i++) {
        const state = states[i];
        const definition = journeyStates[state];
        const events = definition.events || definition.exitEvents || {};

        const eventsByTarget = {};
        Object.entries(events).forEach(([eventName, def]) => {
            let resolvedEventTargets = resolveEventTargets(def, undefined, formData);

            for (let t = 0; t < resolvedEventTargets.length; t++)  {
                const resolvedTarget = resolvedEventTargets[t];

                // Special case for disabling TICF, to match the special case in the journey engine
                if (journeyStates[resolvedTarget.targetState]?.response?.lambda === 'call-ticf-cri' &&
                    formData.getAll('disabledCri').includes('ticf')) {
                    resolvedEventTargets.push(...resolveEventTargets(
                        journeyStates[resolvedTarget.targetState].events.next,
                        undefined,
                        formData
                    ));
                    continue;
                }

            const { targetJourney, targetState, targetEntryEvent, exitEventToEmit, journeyContext } = resolvedTarget;

                const target = exitEventToEmit
                    ? `exit_${exitEventToEmit}`.toUpperCase()
                    : targetJourney
                        ? `${targetJourney}__${targetState}`
                        : targetState;

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
            eventsByTarget[target].push(targetEntryEvent ? `${eventName}/${targetEntryEvent}` : journeyContext ? ` - journeyContext: ${journeyContext}` : eventName);

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
                        journeyStates[target] = {
                            exitEvent: exitEventToEmit,
                        };
                    } else {
                        throw new Error(`Failed to resolve state ${target} from ${state}`);
                    }
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
            nestedJourney: definition.nestedJourney,
        };
    }
    // Click handler serializes the definition to Base64-encoded JSON to avoid escaping issues
    return `    click ${state} call onStateClick(${JSON.stringify(state)}, ${btoa(JSON.stringify(definition.response ?? {}))})`;
};

const renderState = (state, definition) => {
    // Special cases for nested journeys
    if (definition.nestedJourney) {
        return `    ${state}(${state}):::nested_journey`;
    }
    if (definition.exitEvent) {
        return `    ${state}[EXIT\\n${definition.exitEvent}]:::other`;
    }
    if (definition.entryEvent) {
        return `    ${state}[ENTRY\\n${definition.entryEvent}]:::other`;
    }

    // Types for basic nodes
    // process - response.type = process, response.lambda = <lambda>
    // page    - response.type = page, response.pageId = 'page-id'
    // cri     - response.type = cri,
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

export const render = (selectedJourney, journeyMap, nestedJourneys, formData = new FormData()) => {
    const isNestedJourney = selectedJourney in nestedJourneys;
    const direction = topDownJourneys.includes(selectedJourney) ? 'TD' : 'LR';

    // Copy to avoid mutating the input
    const journeyStates = JSON.parse(JSON.stringify(
        isNestedJourney
            ? getNestedJourneyStates(nestedJourneys[selectedJourney])
            : journeyMap.states
    ));

    if (!isNestedJourney && formData.getAll('otherOption').includes('expandNestedJourneys')) {
        // Expand nested journeys first, to allow for two levels of nesting
        Object.values(nestedJourneys)
            .forEach((nestedJourney) => expandNestedJourneys(nestedJourney.nestedJourneyStates, nestedJourneys, formData));
        expandNestedJourneys(journeyStates, nestedJourneys, formData);
    }

    expandParents(journeyStates, journeyMap.states);

    const { transitionsMermaid, states } = formData.getAll('otherOption').includes('onlyOrphanStates')
        ? { transitionsMermaid: '', states: calcOrphanStates(journeyStates) }
        : renderTransitions(journeyStates, formData);

    const { statesMermaid } = renderStates(journeyStates, states);

    return getMermaidGraph(direction, statesMermaid, transitionsMermaid);
};
