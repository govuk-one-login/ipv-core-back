import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";
import svgPanZoom from "https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/+esm";
import yaml from "https://cdn.jsdelivr.net/npm/yaml@2.3.2/+esm";
import { render } from "./render.mjs";
import {
  getJourneyContexts,
  getNestedJourneyStates,
  getOptions,
} from "./helpers.mjs";
import {
  COMMON_JOURNEY_TYPES,
  CRI_NAMES,
  JOURNEY_TYPES,
  NESTED_JOURNEY_TYPES,
} from "./constants.mjs";

const DEFAULT_JOURNEY_TYPE = "INITIAL_JOURNEY_SELECTION";
const NESTED_JOURNEY_TYPE_SEARCH_PARAM = "nestedJourneyType";
const JOURNEY_TYPE_SEARCH_PARAM = "journeyType";

mermaid.initialize({
  maxTextSize: 100000,
  startOnLoad: false,
  // Required to enable links and callbacks
  // This is (relatively) safe, as we only run on our own generated mermaid charts
  securityLevel: "loose",
});

// Page elements
const headerTitleLink = document.getElementById("header-title");
const headerBar = document.getElementById("header-bar");
const headerActions = document.getElementById("header-actions");
const journeySelect = document.getElementById("journey-select");
const headerContent = document.getElementById("header-content");
const headerToggle = document.getElementById("header-toggle");
const form = document.getElementById("configuration-form");
const disabledInput = document.getElementById("disabledInput");
const featureFlagInput = document.getElementById("featureFlagInput");
const otherOptions = document.getElementById("otherOptions");
const nodeTitle = document.getElementById("nodeTitle");
const nodeDef = document.getElementById("nodeDef");
const nodeDesc = document.getElementById("nodeDesc");
const stateSearch = document.getElementById("state-search");
const journeyDesc = document.getElementById("journeyDesc");
const journeyName = document.getElementById("journeyName");
const journeyContextsList = document.getElementById("journeyContextsList");

let svgPanZoomInstance = null;
let journeyMaps = {};
let nestedJourneys = {};

let selectedState = null;

const upperToKebab = (str) => str.toLowerCase().replaceAll("_", "-");

const loadJourneyMaps = async (journeyTypes, subFolder) => {
  const maps = {};
  await Promise.all(
    Object.keys(journeyTypes).map(async (journeyType) => {
      const encodedFilePath = encodeURIComponent(upperToKebab(journeyType));

      const response = await fetch(
        `./${subFolder ? [subFolder, encodedFilePath].join("/") : encodedFilePath}.yaml`,
      );
      maps[journeyType] = yaml.parse(await response.text());
    }),
  );

  return maps;
};

const getPageUrl = (id, context) => {
  const baseUrl = `https://identity.build.account.gov.uk/dev/template/${encodeURIComponent(id)}/en`;
  return context
    ? `${baseUrl}?context=${encodeURIComponent(context)}`
    : baseUrl;
};

const getJourneyUrl = (id) =>
  `?${JOURNEY_TYPE_SEARCH_PARAM}=${encodeURIComponent(id)}`;

const getNestedJourneyUrl = (id) =>
  `?${NESTED_JOURNEY_TYPE_SEARCH_PARAM}=${encodeURIComponent(id)}`;

const switchJourney = async (targetJourney, targetState) => {
  // Update URL
  const params = new URLSearchParams(window.location.search);
  params.delete(NESTED_JOURNEY_TYPE_SEARCH_PARAM);
  params.set(JOURNEY_TYPE_SEARCH_PARAM, targetJourney);
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

const switchToNestedJourney = async (targetNestedJourney) => {
  // Update URL
  const params = new URLSearchParams(window.location.search);
  params.set(NESTED_JOURNEY_TYPE_SEARCH_PARAM, targetNestedJourney);
  window.history.pushState(undefined, undefined, `?${params.toString()}`);

  // Update journey map graph
  await updateView();

  nodeTitle.innerText = targetNestedJourney;
  nodeDef.innerHTML = "";
  nodeDesc.innerHTML = "";
};

const setupHeader = () => {
  // Add header entries for most common journeys
  COMMON_JOURNEY_TYPES.forEach((id) => {
    const link = document.createElement("a");
    link.href = getJourneyUrl(id);
    const label = JOURNEY_TYPES[id];
    link.innerText = label;
    link.onclick = async (e) => {
      e.preventDefault();
      await switchJourney(id, null);
    };
    headerBar.insertBefore(link, headerActions);
  });

  // Add option to journey select for each journey
  Object.entries(JOURNEY_TYPES).forEach(([id, label]) => {
    const option = document.createElement("option");
    option.setAttribute("value", id);
    option.innerText = label;
    journeySelect.append(option);
  });
  journeySelect.onchange = async () => {
    await switchJourney(journeySelect.value, null);
  };
  // Handle user navigating back/forwards
  window.addEventListener("popstate", async () => {
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
  const selectedOptions =
    new URLSearchParams(window.location.search).getAll(name) || [];
  if (options.length) {
    options.forEach((option) => {
      const input = document.createElement("input");
      input.type = "checkbox";
      input.name = name;
      input.value = option;
      input.id = option;
      input.checked = selectedOptions.includes(option) ? "checked" : undefined;
      input.onchange = optionOnChangeHandler(name, input);

      const label = document.createElement("label");
      const span = document.createElement("span");
      span.innerText = (labels && labels[option]) || option;

      label.appendChild(input);
      label.appendChild(span);

      fieldset.appendChild(label);
    });
  } else {
    fieldset.append("N/A");
  }
};

const setupOtherOptions = () => {
  const selectedOptions =
    new URLSearchParams(window.location.search).getAll("otherOption") || [];
  for (const input of otherOptions.getElementsByTagName("input")) {
    input.checked = selectedOptions.includes(input.value)
      ? "checked"
      : undefined;
    input.onchange = optionOnChangeHandler("otherOption", input);
  }
};

const displayJourneyContextInfo = (ctxOptions) => {
  journeyContextsList.innerText = "";
  const ctxHeader = document.createElement("h3");
  ctxHeader.innerText = "Journey Contexts";
  journeyContextsList.append(ctxHeader);

  const ctxDesc = document.createElement("p");
  ctxDesc.innerText = "This journey checks for the following contexts:";
  journeyContextsList.append(ctxDesc);

  const list = document.createElement("ul");
  list.setAttribute("class", "journeyCtxList");
  journeyContextsList.append(list);
  ctxOptions.forEach((ctx) => {
    const bulletPoint = document.createElement("li");
    bulletPoint.innerText = ctx;
    list.append(bulletPoint);
  });
};

const updateView = async () => {
  const formData = new FormData(form);
  const selectedNestedJourney = new URLSearchParams(window.location.search).get(
    NESTED_JOURNEY_TYPE_SEARCH_PARAM,
  );
  const selectedJourney =
    new URLSearchParams(window.location.search).get(
      JOURNEY_TYPE_SEARCH_PARAM,
    ) || DEFAULT_JOURNEY_TYPE;

  if (selectedNestedJourney) {
    const nestedJourneyName =
      nestedJourneys[selectedNestedJourney].name || "Details";
    journeyName.innerText = `${nestedJourneyName} (${journeyMaps[selectedJourney].name})`;
    journeyDesc.innerText = nestedJourneys[selectedNestedJourney].description;
  } else {
    journeyName.innerText = journeyMaps[selectedJourney].name || "Details";
    const desc = journeyMaps[selectedJourney].description;

    journeySelect.value = selectedJourney;
    journeyDesc.innerText = desc || "";
  }

  const ctxOptions = getJourneyContexts(
    selectedNestedJourney
      ? getNestedJourneyStates(nestedJourneys[selectedNestedJourney])
      : journeyMaps[selectedJourney].states,
  );
  if (ctxOptions.length > 0) {
    displayJourneyContextInfo(ctxOptions);
  } else {
    journeyContextsList.innerText = "";
  }

  await renderSvg(selectedJourney, selectedNestedJourney, formData);
};

// Render the journey map SVG
const renderSvg = async (selectedJourney, selectedNestedJourney, formData) => {
  const diagram = render(
    selectedNestedJourney ?? selectedJourney,
    journeyMaps[selectedJourney],
    nestedJourneys,
    formData,
  );
  const diagramElement = document.getElementById("diagram");
  const { svg, bindFunctions } = await mermaid.render("diagramSvg", diagram);
  diagramElement.innerHTML = svg;
  if (bindFunctions) {
    bindFunctions(diagramElement);
  }
  svgPanZoomInstance = svgPanZoom("#diagramSvg", {
    controlIconsEnabled: true,
    dblClickZoomEnabled: false,
    preventMouseEventsDefault: false,
  });
  // Pan to correct header offset
  svgPanZoomInstance.panBy({ x: 0, y: headerContent.offsetHeight / 2 });
};

const highlightState = (state) => {
  // Remove existing highlights
  Array.from(document.getElementsByClassName("highlight")).forEach((edge) =>
    edge.classList.remove("highlight", "outgoingEdge", "incomingEdge"),
  );

  // Add new highlights
  Array.from(document.getElementsByClassName(`LS-${state}`)).forEach((edge) =>
    edge.classList.add("highlight", "outgoingEdge"),
  );
  Array.from(document.getElementsByClassName(`LE-${state}`)).forEach((edge) =>
    edge.classList.add("highlight", "incomingEdge"),
  );
  Array.from(document.getElementsByClassName("node"))
    .filter((node) => node.id.startsWith(`flowchart-${state}-`))
    .forEach((node) => node.classList.add("highlight"));
};

const createLink = (text, href, onClick) => {
  const link = document.createElement("a");
  link.innerText = text;
  link.href = href;
  if (onClick) {
    link.onclick = onClick; // internal targets switch using an event handler
  } else {
    link.target = "_blank"; // external targets should open a new tab
  }
  return link;
};

// Set up the click handlers that mermaid binds to each node
const setupMermaidClickHandlers = () => {
  const getDesc = (response) => {
    switch (response.type) {
      case "process":
        return `Process node executing the '${response.lambda}' lambda.`;
      case "page":
        return `Page node displaying the '${response.pageId}' screen in IPV Core.`;
      case "cri":
        return `CRI node routing to the ${CRI_NAMES[response.criId] || `'${response.criId}' CRI`}.`;
      case "journeyTransition":
        return `Journey transition to the ${response.targetJourney} journey type (${response.targetState}).`;
      case "nestedJourney":
        return `Node representing the ${response.nestedJourney} nested journey.`;
      default:
        return "";
    }
  };

  window.onStateClick = async (state, encodedDef) => {
    const def = JSON.parse(atob(encodedDef));

    // Clicking a node twice opens the link
    if (selectedState === state) {
      if (def.pageId) {
        window.open(getPageUrl(def.pageId, def.context), "_blank");
        return;
      }
      if (def.targetJourney) {
        await switchJourney(def.targetJourney, def.targetState);
        return;
      }
      if (def.nestedJourney) {
        await switchToNestedJourney(def.nestedJourney);
        return;
      }
    }

    // Otherwise, update node information
    selectedState = state;
    highlightState(state);
    nodeTitle.innerText = state;
    nodeDesc.innerHTML = "";
    nodeDef.innerText = JSON.stringify(def, undefined, 2);
    const desc = document.createElement("p");
    desc.innerText = getDesc(def);
    nodeDesc.append(desc);

    if (def.nestedJourney) {
      nodeDesc.append(
        createLink(
          "Click here to view the nested journey",
          getNestedJourneyUrl(def.nestedJourney),
          async (e) => {
            e.preventDefault();
            await switchToNestedJourney(def.nestedJourney);
          },
        ),
      );
    }

    if (def.pageId) {
      nodeDesc.append(
        createLink(
          "Click here to view the page in build",
          getPageUrl(def.pageId, def.context),
        ),
      );
    }

    if (def.type === "journeyTransition") {
      nodeDesc.append(
        createLink(
          "Click here to view the journey",
          getJourneyUrl(def.targetJourney),
          async (e) => {
            e.preventDefault();
            await switchJourney(def.targetJourney, def.targetState);
          },
        ),
      );
    }
  };
};

const setupHeaderToggleClickHandlers = () => {
  headerToggle.addEventListener("click", () => {
    if (headerContent.classList.toggle("hidden")) {
      headerToggle.innerText = "Show header";
    } else {
      headerToggle.innerText = "Hide header";
    }
  });
};

const setupSearchHandler = () => {
  stateSearch.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") {
      return;
    }
    const searchTerm = stateSearch.value.toUpperCase();
    const stateElement = document.querySelector(`g[data-id="${searchTerm}"]`);
    if (!stateElement) {
      console.log(`No state found with selector: g[data-id="${searchTerm}"]`);
      return;
    }
    stateElement.querySelector("span").click(); // Cause the state to be highlighted

    const position = stateElement
      .getAttribute("transform")
      .split("translate(")[1]
      .split(")")[0]
      .split(",");
    const posX = position[0];
    const posY = position[1];

    const currentZoom = svgPanZoomInstance.getZoom();
    const realZoom = svgPanZoomInstance.getSizes().realZoom;
    svgPanZoomInstance.pan({
      x: -(posX * realZoom) + svgPanZoomInstance.getSizes().width / 2,
      y:
        -(posY * realZoom) +
        svgPanZoomInstance.getSizes().height / 2 +
        headerContent.offsetHeight / 2,
    });
    svgPanZoomInstance.zoom(currentZoom);
  });
};

const initialize = async () => {
  setupHeader();
  journeyMaps = await loadJourneyMaps(JOURNEY_TYPES);
  nestedJourneys = await loadJourneyMaps(
    NESTED_JOURNEY_TYPES,
    "nested-journeys",
  );

  const { disabledOptions, featureFlagOptions } = getOptions(
    journeyMaps,
    nestedJourneys,
  );
  setupOptions("disabledCri", disabledOptions, disabledInput, CRI_NAMES);
  setupOptions("featureFlag", featureFlagOptions, featureFlagInput);
  setupOtherOptions();
  setupMermaidClickHandlers();
  setupHeaderToggleClickHandlers();
  form.addEventListener("change", async (event) => {
    event.preventDefault();
    await updateView();
  });
  setupSearchHandler();
  headerTitleLink.onclick = async (e) => {
    e.preventDefault();
    await switchJourney(DEFAULT_JOURNEY_TYPE);
  };
  await updateView();
};

await initialize();
