import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
import svgPanZoom from 'https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/+esm';
import yaml from 'https://cdn.jsdelivr.net/npm/yaml@2.3.2/+esm';
import { getOptions, render } from './render.mjs';

const DEFAULT_JOURNEY_TYPE = 'INITIAL_JOURNEY_SELECTION';

const JOURNEY_TYPES = {
    INITIAL_JOURNEY_SELECTION: 'Initial journey selection',
    NEW_P1_IDENTITY: 'New P1 identity',
    NEW_P2_IDENTITY: 'New P2 identity',
    EVALUATE_SCORES: 'Evaluate scores',
    REUSE_EXISTING_IDENTITY: 'Reuse existing identity',
    UPDATE_NAME: 'Update name',
    UPDATE_ADDRESS: 'Update address',
    INELIGIBLE: 'Ineligible journey',
    FAILED: 'Failed journey',
    TECHNICAL_ERROR: 'Technical error',
    REPEAT_FRAUD_CHECK: 'Repeat fraud check',
    SESSION_TIMEOUT: 'Session timeout',
    F2F_HAND_OFF: 'F2F hand off',
    F2F_PENDING: 'F2F pending',
    F2F_FAILED: 'F2F failed',
    OPERATIONAL_PROFILE_MIGRATION: 'Operational profile migration',
    OPERATIONAL_PROFILE_REUSE: 'Operational profile reuse',
    REVERIFICATION: 'Reverification',
};

const COMMON_JOURNEY_TYPES = [
    'NEW_P2_IDENTITY', 'REUSE_EXISTING_IDENTITY', 'REPEAT_FRAUD_CHECK', 'REVERIFICATION', 'UPDATE_ADDRESS', 'UPDATE_NAME'
];

const CRI_NAMES = {
    address: 'Address',
    claimedIdentity: 'Claimed Identity',
    bav: 'Bank account',
    dcmaw: 'DCMAW (app)',
    drivingLicence: 'Driving licence (web)',
    dwpKbv: 'DWP KBV',
    f2f: 'Face-to-face',
    fraud: 'Experian fraud',
    hmrcKbv: 'HMRC KBV',
    kbv: 'Experian KBV',
    nino: 'HMRC check (NINO)',
    ukPassport: 'Passport (web)',
    ticf: 'TICF',
};

mermaid.initialize({
    startOnLoad: false,
    // Required to enable links and callbacks
    // This is (relatively) safe, as we only run on our own generated mermaid charts
    securityLevel: 'loose',
});

// Page elements
const headerTitleLink = document.getElementById('header-title');
const headerBar = document.getElementById('header-bar');
const headerActions = document.getElementById('header-actions');
const journeySelect = document.getElementById('journey-select');
const headerContent = document.getElementById('header-content');
const headerToggle = document.getElementById('header-toggle');
const form = document.getElementById('configuration-form');
const disabledInput = document.getElementById('disabledInput');
const featureFlagInput = document.getElementById('featureFlagInput')
const otherOptions = document.getElementById('otherOptions');
const nodeTitle = document.getElementById('nodeTitle');
const nodeDef = document.getElementById('nodeDef');
const nodeDesc = document.getElementById('nodeDesc');
const stateSearch = document.getElementById('state-search');
const journeyDesc = document.getElementById('journeyDesc');
const journeyName = document.getElementById('journeyName');

let svgPanZoomInstance = null;
let journeyMaps = {};
let nestedJourneys = {};

let selectedState = null;

const upperToKebab = (str) => str.toLowerCase().replaceAll('_', '-');

const loadJourneyMaps = async () => {
    await Promise.all(Object.keys(JOURNEY_TYPES).map(async (journeyType) => {
        const journeyResponse = await fetch(`./${encodeURIComponent(upperToKebab(journeyType))}.yaml`);
        journeyMaps[journeyType] = yaml.parse(await journeyResponse.text());
    }));
    const nestedResponse = await fetch('./nested-journey-definitions.yaml');
    nestedJourneys = yaml.parse(await nestedResponse.text());
};

const getPageUrl = (id, context) => {
    const baseUrl = `https://identity.build.account.gov.uk/dev/template/${encodeURIComponent(id)}/en`;
    return context ? `${baseUrl}?context=${encodeURIComponent(context)}` : baseUrl;
}

const getJourneyUrl = (id) => `?journeyType=${encodeURIComponent(id)}`;

const switchJourney = async (targetJourney, targetState) => {
    // Update URL
    const params = new URLSearchParams(window.location.search);
    params.set('journeyType', targetJourney);
    window.history.pushState(undefined, undefined, `?${params.toString()}`);

    // Update journey map graph
    await updateView();

    // Update selected state and description
    if (targetState) {
        selectedState = targetState;
        highlightState(targetState);
    }
    nodeTitle.innerText = targetState || "";
    nodeDef.innerHTML = "";
    nodeDesc.innerHTML = "";
};

const setupHeader = () => {
    // Add header entries for most common journies
    COMMON_JOURNEY_TYPES.forEach(id => {
        const link = document.createElement('a');
        link.href = getJourneyUrl(id);
        const label = JOURNEY_TYPES[id];
        link.innerText = label;
        link.onclick = async (e) => {
            e.preventDefault();
            await switchJourney(id, null);
        }
        headerBar.insertBefore(link,  headerActions);
    })

    // Add option to journey select for each journey
    Object.entries(JOURNEY_TYPES).forEach(([id, label]) => {
        const option = document.createElement('option');
        option.setAttribute('value', id)
        option.innerText = label;
        journeySelect.append(option);
    });
    journeySelect.onchange = async (e) => {
        await switchJourney(journeySelect.value, null);
    }
    // Handle user navigating back/forwards
    window.addEventListener('popstate', async () => {
        await updateView();
    });
};

const optionOnChangeHandler = (name, input) => () => {
    const params = new URLSearchParams(window.location.search);
    if (input.checked) {
        params.append(name, input.value);
    } else {
        params.delete(name, input.value);
    }
    window.history.replaceState(undefined, undefined, `?${params.toString()}`);
};

const setupOptions = (name, options, fieldset, labels) => {
    const selectedOptions = new URLSearchParams(window.location.search).getAll(name) || [];
    if (options.length) {
        options.forEach((option) => {
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.name = name;
            input.value = option;
            input.id = option;
            input.checked = selectedOptions.includes(option) ? 'checked' : undefined;
            input.onchange = optionOnChangeHandler(name, input);

            const label = document.createElement('label');
            const span = document.createElement('span');
            span.innerText = (labels && labels[option]) || option;

            label.appendChild(input);
            label.appendChild(span);

            fieldset.appendChild(label);
        });
    } else {
        fieldset.append("N/A")
    }
};

const setupOtherOptions = () => {
    const selectedOptions = new URLSearchParams(window.location.search).getAll('otherOption') || [];
    for (const input of otherOptions.getElementsByTagName('input')) {
        input.checked = selectedOptions.includes(input.value) ? 'checked' : undefined;
        input.onchange = optionOnChangeHandler('otherOption', input);
    }
}

const updateView = async () => {
    const selectedJourney = new URLSearchParams(window.location.search).get('journeyType') || DEFAULT_JOURNEY_TYPE;
    journeyName.innerText = journeyMaps[selectedJourney].name || "Details";
    const desc = journeyMaps[selectedJourney].description;
    const formData = new FormData(form);
    if (desc && formData.has('showJourneyDesc')) {
        journeyDesc.innerText = desc;
    } else {
        journeyDesc.innerText = '';
    }
    journeySelect.value = selectedJourney;
    journeyDesc.innerText = desc || '';

    return renderSvg(selectedJourney, formData);
};

// Render the journey map SVG
const renderSvg = async (selectedJourney, formData) => {
    const diagram = render(selectedJourney, journeyMaps, nestedJourneys, formData);
    const diagramElement = document.getElementById('diagram');
    const { svg, bindFunctions } = await mermaid.render('diagramSvg', diagram);
    diagramElement.innerHTML = svg;
    if (bindFunctions) {
        bindFunctions(diagramElement);
    }
    svgPanZoomInstance = svgPanZoom('#diagramSvg', {
        controlIconsEnabled: true,
        dblClickZoomEnabled: false,
        preventMouseEventsDefault: false,
    });
    // Pan to correct header offset
    svgPanZoomInstance.panBy({ x: 0, y: headerContent.offsetHeight / 2 });
};

const highlightState = (state) => {
    // Remove existing highlights
    Array.from(document.getElementsByClassName('highlight'))
        .forEach((edge) => edge.classList.remove('highlight', 'outgoingEdge', 'incomingEdge'));

    // Add new highlights
    Array.from(document.getElementsByClassName(`LS-${state}`))
        .forEach((edge) => edge.classList.add('highlight', 'outgoingEdge'));
    Array.from(document.getElementsByClassName(`LE-${state}`))
        .forEach((edge) => edge.classList.add('highlight', 'incomingEdge'));
    Array.from(document.getElementsByClassName('node'))
        .filter((node) => node.id.startsWith(`flowchart-${state}-`))
        .forEach((node) => node.classList.add('highlight'));
};

// Set up the click handlers that mermaid binds to each node
const setupMermaidClickHandlers = () => {
    const getDesc = (def) => {
        switch(def.type) {
            case 'process':
                return `Process node executing the '${def.lambda}' lambda.`;
            case 'page':
                return `Page node displaying the \'${def.pageId}\' screen in IPV Core.`;
            case 'cri':
                return `CRI node routing to the ${CRI_NAMES[def.criId] || `'${def.criId}' CRI`}.`;
            case 'journeyTransition':
                return `Journey transition to the ${def.targetJourney} journey type (${def.targetState}).`
            default:
                return '';
        }
    };

    window.onStateClick = async (state, encodedDef) => {
        const def = JSON.parse(atob(encodedDef));

        // Clicking a node twice opens the link
        if (selectedState === state) {
            if (def.pageId) {
                window.open(getPageUrl(def.pageId, def.context), '_blank');
                return;
            }
            if (def.targetJourney) {
                await switchJourney(def.targetJourney, def.targetState);
                return;
            }
        }

        selectedState = state;
        highlightState(state);
        nodeTitle.innerText = state;
        nodeDesc.innerHTML = '';
        nodeDef.innerText = JSON.stringify(def, undefined, 2);
        const desc = document.createElement('p');
        desc.innerText = getDesc(def);
        nodeDesc.append(desc);
        if (def.pageId) {
            const link = document.createElement('a');
            link.innerText = 'Click here to view the page in build';
            link.href = getPageUrl(def.pageId, def.context);
            link.target = '_blank';
            nodeDesc.append(link);
        }
        if (def.type === 'journeyTransition') {
            const link = document.createElement('a');
            link.innerText = 'Click here to view the journey';
            link.href = getJourneyUrl(def.targetJourney);
            link.onclick = async (e) => {
                e.preventDefault();
                await switchJourney(def.targetJourney, def.targetState);
            }
            nodeDesc.append(link);
        }
    };
}

const setupHeaderToggleClickHandlers = () => {
    headerToggle.addEventListener('click', () => {
        if (headerContent.classList.toggle('hidden')) {
            headerToggle.innerText = 'Show header';
        } else {
            headerToggle.innerText = 'Hide header';
        }
    });
}

const setupSearchHandler = () => {
    stateSearch.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter') {
            return;
        }
        const searchTerm = stateSearch.value.toUpperCase();
        const stateElement = document.querySelector(`g[data-id="${searchTerm}"]`);
        if (!stateElement) {
            console.log(`No state found with selector: g[data-id="${searchTerm}"]`)
            return;
        }
        stateElement.querySelector('span').click(); // Cause the state to be highlighted

        const position = stateElement.getAttribute('transform').split("translate(")[1].split(")")[0].split(",");
        const posX = position[0];
        const posY = position[1];

        const currentZoom = svgPanZoomInstance.getZoom();
        const realZoom = svgPanZoomInstance.getSizes().realZoom;
        svgPanZoomInstance.pan({
            x: -(posX*realZoom) + (svgPanZoomInstance.getSizes().width/2),
            y: -(posY*realZoom) + (svgPanZoomInstance.getSizes().height/2) + (headerContent.offsetHeight/2)
        });
        svgPanZoomInstance.zoom(currentZoom);
    })
}

const initialize = async () => {
    setupHeader();
    await loadJourneyMaps();
    const { disabledOptions, featureFlagOptions } = getOptions(journeyMaps);
    setupOptions('disabledCri', disabledOptions, disabledInput, CRI_NAMES);
    setupOptions('featureFlag', featureFlagOptions, featureFlagInput);
    setupOtherOptions();
    setupMermaidClickHandlers();
    setupHeaderToggleClickHandlers();
    form.addEventListener('change', async (event) => {
        event.preventDefault();
        await updateView();
    });
    setupSearchHandler();
    headerTitleLink.onclick = async (e) => {
        e.preventDefault();
        await switchJourney(DEFAULT_JOURNEY_TYPE);
      };
    await updateView();
}

await initialize();
