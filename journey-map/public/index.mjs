import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
import svgPanZoom from 'https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/+esm';
import yaml from 'https://cdn.jsdelivr.net/npm/yaml@2.3.2/+esm';
import { getOptions, render } from './render.mjs';

const DEFAULT_JOURNEY_TYPE = 'INITIAL_JOURNEY_SELECTION';

const JOURNEY_TYPES = {
    INITIAL_JOURNEY_SELECTION: 'Initial journey selection',
    NEW_P2_IDENTITY: 'New P2 identity',
    REUSE_EXISTING_IDENTITY: 'Reuse existing identity',
    INELIGIBLE: 'Ineligible journey',
    FAILED: 'Failed journey',
    TECHNICAL_ERROR: 'Technical error',
    SESSION_TIMEOUT: 'Session timeout',
    F2F_PENDING: 'F2F pending',
    F2F_FAILED: 'F2F failed',
    OPERATIONAL_PROFILE_MIGRATION: 'Operational profile migration',
    OPERATIONAL_PROFILE_REUSE: 'Operational profile reuse',
};

const CRI_NAMES = {
    address: 'Address CRI',
    claimedIdentity: 'Claimed Identity CRI',
    bav: 'Bank account CRI',
    dcmaw: 'DCMAW (app) CRI',
    drivingLicence: 'Driving licence (web) CRI',
    f2f: 'Face-to-face CRI',
    fraud: 'Experian fraud CRI',
    hmrcKbv: 'HMRC KBV CRI',
    kbv: 'Experian KBV CRI',
    nino: 'NINO CRI',
    ukPassport: 'Passport (web) CRI',
    ticf: 'TICF CRI',
};

mermaid.initialize({
    startOnLoad: false,
    // Required to enable links and callbacks
    // This is (relatively) safe, as we only run on our own generated mermaid charts
    securityLevel: 'loose',
});

// Page elements
const headerBar = document.getElementById('header-bar');
const headerContent = document.getElementById('header-content');
const headerToggle = document.getElementById('header-toggle');
const form = document.getElementById('configuration-form');
const disabledInput = document.getElementById('disabledInput');
const featureFlagInput = document.getElementById('featureFlagInput')
const nodeTitle = document.getElementById('nodeTitle');
const nodeDef = document.getElementById('nodeDef');
const nodeDesc = document.getElementById('nodeDesc');

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

const getPageUrl = (id) => `https://identity.build.account.gov.uk/dev/template/${encodeURIComponent(id)}/en`;
const getJourneyUrl = (id) => `?journeyType=${encodeURIComponent(id)}`;

const switchJourney = async (journeyType) => {
    window.history.pushState(undefined, undefined, getJourneyUrl(journeyType));
    selectedState = null;
    await renderSvg();
};

const setupHeader = () => {
    // Add header entries for each journey
    Object.entries(JOURNEY_TYPES).forEach(([id, label]) => {
        const link = document.createElement('a');
        link.href = getJourneyUrl(id);
        link.innerText = label;
        link.onclick = async (e) => {
            e.preventDefault();
            await switchJourney(id);
        }
        headerBar.appendChild(link);
    });

    // Handle user navigating back/forwards
    window.addEventListener('popstate', async () => {
        await renderSvg();
    });
};

const setupOptions = (name, options, fieldset, labels) => {
    if (options.length) {
        options.forEach((option) => {
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.name = name;
            input.value = option;
            input.id = option;

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

// Render the journey map SVG
const renderSvg = async () => {
    const selectedJourney = new URLSearchParams(window.location.search).get('journeyType') || DEFAULT_JOURNEY_TYPE;
    const diagram = render(journeyMaps[selectedJourney], nestedJourneys, new FormData(form));
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
                window.open(getPageUrl(def.pageId), '_blank');
                return;
            }
            if (def.targetJourney) {
                await switchJourney(def.targetJourney);
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
            link.href = getPageUrl(def.pageId);
            if (def.context) {
                link.href += `?context=${def.context}`;
            }
            link.target = '_blank';
            nodeDesc.append(link);
        }
        if (def.type === 'journeyTransition') {
            const link = document.createElement('a');
            link.innerText = 'Click here to view the journey';
            link.href = getJourneyUrl(def.targetJourney);
            link.onclick = async (e) => {
                e.preventDefault();
                await switchJourney(def.targetJourney);
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

const initialize = async () => {
    setupHeader();
    await loadJourneyMaps();
    const { disabledOptions, featureFlagOptions } = getOptions(journeyMaps);
    setupOptions('disabledCri', disabledOptions, disabledInput, CRI_NAMES);
    setupOptions('featureFlag', featureFlagOptions, featureFlagInput);
    setupMermaidClickHandlers();
    setupHeaderToggleClickHandlers();
    form.addEventListener('change', async (event) => {
        event.preventDefault();
        await renderSvg();
    });
    await renderSvg();
}

await initialize();
