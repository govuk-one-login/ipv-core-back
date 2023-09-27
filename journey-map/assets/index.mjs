const initialStates = ['INITIAL_IPV_JOURNEY', 'CORE_SESSION_TIMEOUT'];

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

        Object.entries(events).map(([eventName, def]) => {
            const target = resolveEventTarget(def, options);
            if (!states.includes(target)) {
                states.push(target);
            }
            stateTransitions.push(`    ${state}-->|${eventName}|${target}`);
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
                return `    ${state}[${state}\\n${definition.response.pageId}]:::page`;
            case 'cri':
                return `    ${state}([${state}\\n${definition.response.criId}]):::cri`;
            default:
                return `    ${state}`;
        }
    });

    return { statesMermaid: mermaids.join('\n') };
};

export const render = (journeyMap, options = {}) => {
    const { transitionsMermaid, states } = renderTransitions(journeyMap, options);
    const { statesMermaid } = renderStates(journeyMap, states);

    const mermaid =
`graph LR
    classDef process fill:#ffa
    classDef page fill:#afa;
    classDef cri fill:#faf;
${statesMermaid}
${transitionsMermaid}
`;

    return mermaid;
};
