import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
import svgPanZoom from 'https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/+esm';
import yaml from 'https://cdn.jsdelivr.net/npm/yaml@2.3.2/+esm';
import { getOptions, render } from './render.mjs';

const CRI_NAMES = {
    address: 'Address CRI',
    claimedIdentity: 'Claimed Identity CRI',
    bav: 'Bank account CRI',
    dcmaw: 'DCMAW (mobile app) CRI',
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
const form = document.getElementById('configuration-form');
const disabledInput = document.getElementById('disabledInput');
const featureFlagInput = document.getElementById('featureFlagInput')
const nodeTitle = document.getElementById('nodeTitle');
const nodeDef = document.getElementById('nodeDef');
const nodeDesc = document.getElementById('nodeDesc');

// Load the journey map
const journeyResponse = await fetch('./ipv-core-main-journey.yaml');
const journeyMap = yaml.parse(await journeyResponse.text());
const nestedResponse = await fetch('./nested-journey-definitions.yaml');
const nestedJourneys = yaml.parse(await nestedResponse.text());

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
    const diagram = render(journeyMap, nestedJourneys, new FormData(form));
    const diagramElement = document.getElementById('diagram');
    const { svg, bindFunctions } = await mermaid.render('diagramSvg', diagram);
    diagramElement.innerHTML = svg;
    if (bindFunctions) {
        bindFunctions(diagramElement);
    }
    svgPanZoom('#diagramSvg', { controlIconsEnabled: true });
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
            default:
                return '';
        }
    };

    window.onStateClick = (state, encodedDef) => {
        highlightState(state);
        nodeTitle.innerText = state;
        nodeDesc.innerHTML = '';
        const def = JSON.parse(atob(encodedDef));
        nodeDef.innerText = JSON.stringify(def, undefined, 2);
        const desc = document.createElement('p');
        desc.innerText = getDesc(def);
        nodeDesc.append(desc);
        if (def.pageId) {
            const link = document.createElement('a');
            link.innerText = 'Click here to view the page in build';
            link.href = `https://identity.build.account.gov.uk/ipv/page/${encodeURIComponent(def.pageId)}?preview=true&lng=en`;
            link.target = '_blank';
            nodeDesc.append(link);
        }
    };
}

const initialize = async () => {
    const { disabledOptions, featureFlagOptions } = getOptions(journeyMap);
    setupOptions('disabledCri', disabledOptions, disabledInput, CRI_NAMES);
    setupOptions('featureFlag', featureFlagOptions, featureFlagInput);
    setupMermaidClickHandlers();
    form.addEventListener('change', async (event) => {
        event.preventDefault();
        await renderSvg();
    });
    await renderSvg();
}

await initialize();
