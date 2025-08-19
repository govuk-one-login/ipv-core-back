import { ERROR_JOURNEYS, FAILURE_JOURNEYS } from "../constants.js";
import { JourneyState } from "../types.js";

const JOURNEY_CONTEXT_TRANSITION_CLASSNAME = "journeyCtxTransition";
const MITIGATIONS_TRANSITION_CLASSNAME = "mitigationTransition";

export const getMermaidHeader = (graphDirection: "TD" | "LR"): string =>
  // These styles should be kept in sync with the key in style.css
  `flowchart ${graphDirection}
    classDef process fill:#ffa,stroke:#000;
    classDef page fill:#ae8,stroke:#000;
    classDef cri fill:#faf,stroke:#000;
    classDef journey_transition fill:#aaf,stroke:#000;
    classDef error_transition fill:#f99,stroke:#000;
    classDef other fill:#f3f2f1,stroke:#000;
    classDef nested_journey fill:#aaedff,stroke:#000;`;

export interface StateNode {
  name: string;
  definition: JourneyState;
}

export const renderState = ({ name, definition }: StateNode): string => {
  // Special cases for synthetic states
  if (definition.exitEvent) {
    return `    ${name}[EXIT\n${definition.exitEvent}]:::other`;
  }
  if (definition.entryEvent) {
    return `    ${name}[ENTRY\n${definition.entryEvent}]:::other`;
  }

  // Types for basic nodes
  // process - response.type = process, response.lambda = <lambda>
  // page    - response.type = page, response.pageId = 'page-id'
  // cri     - response.type = cri,
  switch (definition.response?.type) {
    case "process":
      return `    ${name}(${name}\n${definition.response.lambda}):::process`;
    case "page":
    case "error":
      return `    ${name}[${name}\n${definition.response.pageId}]:::page`;
    case "cri": {
      const contextInfo = definition.response.context
        ? `\n context: ${definition.response.context}`
        : "";
      return `    ${name}([${name}\n${definition.response.criId}${contextInfo}]):::cri`;
    }
    case "nestedJourney":
      return `    ${name}(${name}\n${definition.response.nestedJourney}):::nested_journey`;
    case "journeyTransition": {
      const { targetJourney, targetState } = definition.response;
      return FAILURE_JOURNEYS.includes(targetJourney as string) ||
        ERROR_JOURNEYS.includes(targetJourney as string)
        ? `    ${name}(${targetJourney}\n${targetState}):::error_transition`
        : `    ${name}(${targetJourney}\n${targetState}):::journey_transition`;
    }
    default:
      return `    ${name}:::other`;
  }
};

export const renderClickHandler = ({ name, definition }: StateNode): string => {
  // Click handler serializes the definition to Base64-encoded JSON to avoid escaping issues
  return `    click ${name} call onStateClick(${JSON.stringify(name)}, ${btoa(JSON.stringify(definition.response ?? {}))})`;
};

export interface TransitionEvent {
  eventName: string;
  targetJourney?: string;
  targetEntryEvent?: string;
  journeyContext?: string;
  mitigation?: string;
}

export interface TransitionEdge {
  sourceState: string;
  targetState: string;
  transitionCount?: number;
  transitionEvents: TransitionEvent[];
}

const createTransitionLabel = ({
  eventName,
  targetEntryEvent,
  journeyContext,
  mitigation,
}: TransitionEvent): string => {
  const eventLabel = `${eventName}${targetEntryEvent ? `/${targetEntryEvent}` : ""}`;

  const createEventHtmlLabel = (
    label?: string,
    value?: string,
    className?: string,
  ): string =>
    `<p class="defaultEdgeLabel${className ? ` ${className}` : ""}">${eventLabel}${label ? ` - ${label}: ${value}` : ""}</p>`;

  if (journeyContext) {
    return createEventHtmlLabel(
      "journeyContext",
      journeyContext,
      JOURNEY_CONTEXT_TRANSITION_CLASSNAME,
    );
  }

  if (mitigation) {
    return createEventHtmlLabel(
      "mitigation",
      mitigation,
      MITIGATIONS_TRANSITION_CLASSNAME,
    );
  }

  return createEventHtmlLabel();
};

export const renderTransition = ({
  sourceState,
  targetState,
  transitionCount,
  transitionEvents,
}: TransitionEdge): string => {
  const label = transitionEvents.map(createTransitionLabel).join("\n");
  return `    ${sourceState} ${sourceState}-${targetState}@-->|${label}\n#${transitionCount}|${targetState}`;
};
