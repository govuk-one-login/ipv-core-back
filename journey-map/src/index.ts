import mermaid from "mermaid";
import svgPanZoom from "svg-pan-zoom";
import yaml from "yaml";
import { render } from "./render.js";
import { getAsFullJourneyMap } from "./helpers/uplift-nested.js";
import {
  COMMON_JOURNEY_TYPES,
  CRI_NAMES,
  Environment,
  JOURNEY_TYPES,
  NESTED_JOURNEY_TYPES,
} from "./constants.js";
import { JourneyMap, JourneyResponse, NestedJourneyMap } from "./types.js";
import { parseOptions, RenderOptions } from "./helpers/options.js";
import { getJourneyContexts } from "./helpers/journey-context.js";
import { JourneyTransition, setJourneyTransitionsData } from "./data/data.js";
import {
  getJourneyTransitions,
  getSystemSettings,
  mapStringToEnvironment,
} from "./service/analyticsService.js";
import { parseTransitionsApiForm } from "./helpers/analytics.js";
import { enrichJourneyTransitionData } from "./helpers/enrich-transitions.js";

type ClickHandler = (e: MouseEvent) => void;

declare global {
  interface Window {
    // Used to define a click handler for use in the mermaid
    onStateClick?: (state: string, encodedDef: string) => void;
  }
  interface Element {
    style: {
      stroke?: string;
    };
    // Used to keep track of the previous colour or a path
    previousColour?: string;
  }
}

const DEFAULT_JOURNEY_TYPE = "INITIAL_JOURNEY_SELECTION";
const NESTED_JOURNEY_TYPE_SEARCH_PARAM = "nestedJourneyType";
const JOURNEY_TYPE_SEARCH_PARAM = "journeyType";

mermaid.initialize({
  maxTextSize: 200000,
  startOnLoad: false,
  // Required to enable links and callbacks
  // This is (relatively) safe, as we only run on our own generated mermaid charts
  securityLevel: "loose",
  flowchart: {
    useMaxWidth: false,
    wrappingWidth: 800,
  },
});

// Page elements
const diagramElement = document.getElementById("diagram") as HTMLDivElement;
const headerTitleLink = document.getElementById(
  "header-title",
) as HTMLAnchorElement;
const headerBar = document.getElementById("header-bar") as HTMLDivElement;
const headerActions = document.getElementById(
  "header-actions",
) as HTMLDivElement;
const journeySelect = document.getElementById(
  "journey-select",
) as HTMLSelectElement;
const headerContent = document.getElementById(
  "header-content",
) as HTMLDivElement;
const headerToggle = document.getElementById(
  "header-toggle",
) as HTMLButtonElement;
const transitionsForm = document.getElementById(
  "transitions-traffic-form",
) as HTMLFormElement;
const transitionsFromInput = document.getElementById(
  "transitionsFromInput",
) as HTMLInputElement;
const transitionsToInput = document.getElementById(
  "transitionsToInput",
) as HTMLInputElement;
const transitionsSubmitButton = document.getElementById(
  "form-button",
) as HTMLButtonElement;
const systemSettingsSelection = document.getElementById(
  "systemSettingsTargetEnv",
) as HTMLSelectElement;
const coreBackConfigForm = document.getElementById(
  "configuration-form",
) as HTMLFormElement;
const otherOptionsForm = document.getElementById(
  "journey-map-configuration-form",
) as HTMLFormElement;
const disabledInput = document.getElementById(
  "disabledInput",
) as HTMLFieldSetElement;
const featureFlagInput = document.getElementById(
  "featureFlagInput",
) as HTMLFieldSetElement;
const otherOptions = document.getElementById(
  "otherOptions",
) as HTMLFieldSetElement;
const nodeTitle = document.getElementById("nodeTitle") as HTMLHeadingElement;
const nodeDef = document.getElementById("nodeDef") as HTMLPreElement;
const nodeDesc = document.getElementById("nodeDesc") as HTMLDivElement;
const journeyDesc = document.getElementById("journeyDesc") as HTMLDivElement;
const journeyName = document.getElementById(
  "journeyName",
) as HTMLHeadingElement;
const journeyContextsList = document.getElementById(
  "journeyContextsList",
) as HTMLDivElement;

let svgPanZoomInstance: SvgPanZoom.Instance | null = null;
let journeyMaps: Record<string, JourneyMap> = {};
let nestedJourneys: Record<string, NestedJourneyMap> = {};

let selectedState: string | null = null;

const upperToKebab = (str: string): string =>
  str.toLowerCase().replaceAll("_", "-");

const loadJourneyMaps = async <T>(
  journeyTypes: Record<string, string>,
  subFolder?: string,
): Promise<Record<string, T>> => {
  const maps: Record<string, T> = {};
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

const getPageUrl = (id: string, context?: string): string => {
  const baseUrl = `https://identity.build.account.gov.uk/dev/template/${encodeURIComponent(id)}/en`;
  return context
    ? `${baseUrl}?context=${encodeURIComponent(context)}`
    : baseUrl;
};

const getJourneyUrl = (id: string): string =>
  `?${JOURNEY_TYPE_SEARCH_PARAM}=${encodeURIComponent(id)}`;

const getNestedJourneyUrl = (id: string): string =>
  `?${NESTED_JOURNEY_TYPE_SEARCH_PARAM}=${encodeURIComponent(id)}`;

const switchJourney = async (
  targetJourney: string,
  targetState?: string,
): Promise<void> => {
  // Update URL
  const params = new URLSearchParams(window.location.search);
  params.delete(NESTED_JOURNEY_TYPE_SEARCH_PARAM);
  params.set(JOURNEY_TYPE_SEARCH_PARAM, targetJourney);
  window.history.pushState(undefined, "", `?${params.toString()}`);

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

const switchToNestedJourney = async (
  targetNestedJourney: string,
): Promise<void> => {
  // Update URL
  const params = new URLSearchParams(window.location.search);
  params.set(NESTED_JOURNEY_TYPE_SEARCH_PARAM, targetNestedJourney);
  window.history.pushState(undefined, "", `?${params.toString()}`);

  // Update journey map graph
  await updateView();

  nodeTitle.innerText = targetNestedJourney;
  nodeDef.innerHTML = "";
  nodeDesc.innerHTML = "";
};

const setupHeader = (): void => {
  // Add header entries for most common journeys
  COMMON_JOURNEY_TYPES.forEach((id) => {
    const link = document.createElement("a");
    link.href = getJourneyUrl(id);
    const label = JOURNEY_TYPES[id];
    link.innerText = label;
    link.onclick = async (e) => {
      e.preventDefault();
      await switchJourney(id);
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
    await switchJourney(journeySelect.value);
  };
  // Handle user navigating back/forwards
  window.addEventListener("popstate", async () => {
    await updateView();
  });
};

const optionOnChangeHandler =
  (name: string, input: HTMLInputElement) => (): void => {
    const params = new URLSearchParams(window.location.search);
    if (input.checked) {
      params.append(name, input.value);
    } else {
      params.delete(name, input.value);
    }
    window.history.replaceState(undefined, "", `?${params.toString()}`);
  };

const setupOptions = (
  name: string,
  options: Record<string, boolean>,
  fieldset: HTMLFieldSetElement,
  labels?: Record<string, string>,
): void => {
  const selectedOptions = Object.entries(options)
    .filter(([, value]) => value)
    .map(([key]) => key);

  const optionKeys = Object.keys(options);
  if (optionKeys.length) {
    optionKeys.forEach((option) => {
      const input = document.createElement("input");
      input.type = "checkbox";
      input.name = name;
      input.value = option;
      input.id = option;
      input.checked = selectedOptions.includes(option);
      input.onchange = optionOnChangeHandler(name, input);

      const span = document.createElement("span");
      span.innerText = (labels && labels[option]) || option;

      const label = document.createElement("label");
      label.appendChild(input);
      label.appendChild(span);

      fieldset.appendChild(label);
    });
  } else {
    fieldset.append("N/A");
  }
};

const clearOptions = (...fieldsets: HTMLFieldSetElement[]) => {
  fieldsets.forEach((fieldset) => {
    const labels = fieldset.querySelectorAll<HTMLInputElement>("label");
    labels.forEach((label) => label.remove());
  });
};

const disableOptions = (...fieldsets: HTMLFieldSetElement[]) => {
  fieldsets.forEach((fieldset) => {
    const inputs = fieldset.querySelectorAll<HTMLInputElement>("input");
    inputs.forEach((input) => (input.disabled = true));
  });
};

const setupSystemSettingsOptions = async (targetEnvironment: Environment) => {
  const systemSettings = await getSystemSettings(targetEnvironment);
  if (!systemSettings) {
    return;
  }
  const disabledCris =
    systemSettings?.criStatuses &&
    Object.fromEntries(
      Object.entries(systemSettings?.criStatuses).map(([cri, enabled]) => [
        cri,
        !enabled,
      ]),
    );
  clearOptions(disabledInput, featureFlagInput);
  setupOptions("disabledCri", disabledCris ?? {}, disabledInput, CRI_NAMES);
  setupOptions(
    "featureFlag",
    systemSettings?.featureFlagStatuses ?? {},
    featureFlagInput,
  );
};

const setupOtherOptions = (): void => {
  const selectedOptions =
    new URLSearchParams(window.location.search).getAll("otherOption") || [];
  for (const input of otherOptions.getElementsByTagName("input")) {
    input.checked = selectedOptions.includes(input.value);
    input.onchange = optionOnChangeHandler("otherOption", input);
  }
};

const displayJourneyContextInfo = (ctxOptions: string[]): void => {
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

const updateView = async (): Promise<void> => {
  const options = parseOptions(
    new FormData(coreBackConfigForm),
    new FormData(otherOptionsForm),
  );
  const selectedNestedJourney = new URLSearchParams(window.location.search).get(
    NESTED_JOURNEY_TYPE_SEARCH_PARAM,
  );
  const selectedJourney =
    new URLSearchParams(window.location.search).get(
      JOURNEY_TYPE_SEARCH_PARAM,
    ) || DEFAULT_JOURNEY_TYPE;

  const journeyMap = selectedNestedJourney
    ? getAsFullJourneyMap(nestedJourneys[selectedNestedJourney])
    : journeyMaps[selectedJourney];

  journeyName.innerText = journeyMap.name || "Details";
  journeySelect.value = selectedJourney;
  journeyDesc.innerText = journeyMap.description || "";

  const ctxOptions = getJourneyContexts(journeyMap.states);
  if (ctxOptions.length > 0) {
    displayJourneyContextInfo(ctxOptions);
  } else {
    journeyContextsList.innerText = "";
  }

  await renderSvg(selectedJourney, selectedNestedJourney, options);
};

const highlightEdgeAndLabel = (edge: Element, edgeLabel: Element) => {
  // Reset all edges and paths to default styling
  Array.from(document.querySelectorAll(`g.edgePaths path`))
    .filter((edge) => edge.style.stroke === "black")
    .forEach((edge) => (edge.style.stroke = edge.previousColour));
  Array.from(document.getElementsByClassName("edgeLabelIdentifier")).forEach(
    (edgeLabel) => edgeLabel.classList.remove("edgeLabelIdentifier"),
  );

  edge.style.stroke = "black";
  edgeLabel.classList.add("edgeLabelIdentifier");
};

const setEdgeAndLabelClickHandlers = (edgeIds: string[]) => {
  const edgeLabels = document.querySelectorAll("span.edgeLabel");
  edgeLabels.forEach((label, idx) => {
    // There isn't a native way in mermaid.js to add an id to the
    // edge labels so we manually add them after the diagram
    // has been rendered onto the dom
    label.id = edgeIds[idx];
    label.addEventListener("click", () => {
      const edge = document.querySelector(`path[id^=${label.id}]`);
      if (edge) {
        highlightEdgeAndLabel(edge, label);
      }
    });
  });

  const edges = document.querySelectorAll("g.edgePaths path");
  edges.forEach((edge) => {
    edge.previousColour = edge.style.stroke;
    edge.addEventListener("click", () => {
      const label = document.querySelector(`span[id=${edge.id}]`);
      if (label) {
        highlightEdgeAndLabel(edge, label);
      }
    });
  });
};

// Render the journey map SVG
const renderSvg = async (
  selectedJourney: string,
  selectedNestedJourney: string | null,
  options: RenderOptions,
): Promise<void> => {
  const { mermaidString: diagram, edgeIds } = await render(
    selectedNestedJourney ?? selectedJourney,
    journeyMaps[selectedJourney],
    nestedJourneys,
    options,
    journeyMaps,
  );
  const { svg, bindFunctions } = await mermaid.render("diagramSvg", diagram);
  diagramElement.innerHTML = svg;
  if (bindFunctions) {
    bindFunctions(diagramElement);
  }

  // There isn't a native way in mermaid.js to add event handlers
  // to edges and their labels so we create them once the svg
  // has been rendered onto the dom
  setEdgeAndLabelClickHandlers(edgeIds);

  svgPanZoomInstance = svgPanZoom("#diagramSvg", {
    controlIconsEnabled: true,
    dblClickZoomEnabled: false,
    preventMouseEventsDefault: false,
  });
  // Pan to correct header offset
  svgPanZoomInstance.panBy({ x: 0, y: headerContent.offsetHeight / 2 });
};

const highlightState = (state: string): void => {
  // Remove existing highlights
  Array.from(document.getElementsByClassName("highlight")).forEach((edge) =>
    edge.classList.remove("highlight", "outgoingEdge", "incomingEdge"),
  );

  // Add new highlights
  Array.from(document.querySelectorAll(`path[id^="${state}-"]`)).forEach(
    (edge) => edge.classList.add("highlight", "outgoingEdge"),
  );
  Array.from(document.querySelectorAll(`path[id$="-${state}"]`)).forEach(
    (edge) => edge.classList.add("highlight", "incomingEdge"),
  );
  Array.from(document.getElementsByClassName("node"))
    .filter((node) => node.id.startsWith(`flowchart-${state}-`))
    .forEach((node) => node.classList.add("highlight"));
};

const createLink = (
  text: string,
  href: string,
  onClick?: ClickHandler,
): HTMLAnchorElement => {
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
const setupMermaidClickHandlers = (): void => {
  const getDesc = (response: JourneyResponse): string => {
    switch (response.type) {
      case "process":
        return `Process node executing the '${response.lambda}' lambda.`;
      case "page":
        return `Page node displaying the '${response.pageId}' screen in IPV Core.`;
      case "cri":
        return `CRI node routing to the ${CRI_NAMES[response.criId as string] || `'${response.criId}' CRI`}.`;
      case "journeyTransition":
        return `Journey transition to the ${response.targetJourney} journey type (${response.targetState}).`;
      case "nestedJourney":
        return `Node representing the ${response.nestedJourney} nested journey.`;
      default:
        return "";
    }
  };

  window.onStateClick = async (
    state: string,
    encodedDef: string,
  ): Promise<void> => {
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

const setupHeaderToggleClickHandlers = (): void => {
  headerToggle.addEventListener("click", () => {
    if (headerContent.classList.toggle("hidden")) {
      headerToggle.innerText = "Show header";
    } else {
      headerToggle.innerText = "Hide header";
    }
  });
};

const toDateTimeLocalString = (date: Date): string => {
  const pad = (n: number): string => n.toString().padStart(2, "0");
  // Converts date to YYYY-MM-DDTHH:MM format
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
};

const setupJourneyTransitionInput = (): void => {
  const now = toDateTimeLocalString(new Date());
  const nowMinus30Min = toDateTimeLocalString(
    new Date(Date.now() - 30 * 60 * 1000),
  );
  transitionsToInput.value = now;
  transitionsFromInput.value = nowMinus30Min;
  transitionsToInput.min = nowMinus30Min;
  transitionsFromInput.max = now;

  transitionsFromInput.addEventListener("change", () => {
    if (transitionsFromInput.value > transitionsToInput.value) {
      transitionsToInput.value = transitionsFromInput.value;
    }
    transitionsToInput.min = transitionsFromInput.value;
  });

  transitionsToInput.addEventListener("change", () => {
    if (transitionsToInput.value < transitionsFromInput.value) {
      transitionsFromInput.value = transitionsToInput.value;
    }
    transitionsFromInput.max = transitionsToInput.value;
  });

  transitionsForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    transitionsSubmitButton.disabled = true;
    const requestBody = parseTransitionsApiForm(new FormData(transitionsForm));

    const journeyTransitions: JourneyTransition[] = await getJourneyTransitions(
      requestBody,
    ).finally(() => {
      transitionsSubmitButton.disabled = false;
    });
    enrichJourneyTransitionData(
      journeyTransitions,
      journeyMaps,
      nestedJourneys,
    );
    setJourneyTransitionsData(journeyTransitions);
    await updateView();
  });
};

const initialize = async (): Promise<void> => {
  setupJourneyTransitionInput();
  setupHeader();
  journeyMaps = await loadJourneyMaps(JOURNEY_TYPES);
  nestedJourneys = await loadJourneyMaps(
    NESTED_JOURNEY_TYPES,
    "nested-journeys",
  );
  await setupSystemSettingsOptions(Environment.PRODUCTION);
  setupOtherOptions();
  setupMermaidClickHandlers();
  setupHeaderToggleClickHandlers();

  systemSettingsSelection.addEventListener("change", async () => {
    const selectionValue = systemSettingsSelection.value;
    const targetEnvironment = mapStringToEnvironment(selectionValue);
    disableOptions(disabledInput, featureFlagInput);
    await setupSystemSettingsOptions(targetEnvironment);
    await updateView();
  });

  coreBackConfigForm.addEventListener("change", async (event) => {
    event.preventDefault();
    await updateView();
  });
  otherOptionsForm.addEventListener("change", async (event) => {
    event.preventDefault();
    await updateView();
  });
  headerTitleLink.onclick = async (e) => {
    e.preventDefault();
    await switchJourney(DEFAULT_JOURNEY_TYPE);
  };
  await updateView();
};

initialize().catch(console.error);
