export interface JourneyMap {
  name: string;
  description: string;
  states: Record<string, JourneyState>;
}

export type JourneyState =
  | BasicJourneyState
  | NestedJourneyState
  | EntryJourneyState
  | ExitJourneyState;

export interface BasicJourneyState {
  journeyContext?: string;
  response?: JourneyResponse;
  events: Record<string, JourneyEvent>;
  exitEvents?: undefined;
}

export interface NestedJourneyState {
  nestedJourney: string;
  events?: undefined;
  exitEvents: Record<string, JourneyEvent>;
}

// Synthetic state used when rendering nested journeys
export interface EntryJourneyState extends BasicJourneyState {
  entryEvent: string;
}

// Synthetic state used when rendering nested journeys
export interface ExitJourneyState extends BasicJourneyState {
  exitEvent: string;
}

export type JourneyResponse =
  | PageResponse
  | ProcessResponse
  | CriResponse
  | ErrorResponse
  | TransitionResponse
  | NestedJourneyResponse;

export interface PageResponse {
  type: "page";
  pageId: string;
  context?: string;
}

export interface ProcessResponse {
  type: "process";
  lambda: string;
  lambdaInput?: object;
}

export interface CriResponse {
  type: "cri";
  criId: string;
}

export interface ErrorResponse {
  type: "error";
  pageId: string;
  statusCode: number;
}

// Synthetic response used when rendering journey transitions
export interface TransitionResponse {
  type: "journeyTransition";
  targetJourney: string;
  targetState: string;
}

// Synthetic response used when rendering journey transitions
export interface NestedJourneyResponse {
  type: "nestedJourney";
  nestedJourney: string;
}

export interface JourneyEvent {
  targetState: string;
  targetJourney?: string;
  targetEntryEvent?: string;

  checkIfDisabled?: Record<string, JourneyEvent>;
  checkFeatureFlag?: Record<string, JourneyEvent>;
  checkJourneyContext?: Record<string, JourneyEvent>;
  checkMitigation?: Record<string, JourneyEvent>;

  auditEvents?: string[];
  auditContext?: Record<string, string>;

  // Not present in the definition, used when rendering context-specific events
  journeyContext?: string;

  // Not present in the definition, used when rendering mitigation-specific events
  mitigation?: string;
}

export interface NestedJourneyMap {
  name: string;
  description: string;
  entryEvents: Record<string, JourneyEvent>;
  nestedJourneyStates: Record<string, JourneyState>; // TODO: do we need a nested state here, which allows for exit events?
}
