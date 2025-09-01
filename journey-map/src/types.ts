export interface JourneyMap {
  name: string;
  description: string;
  states: Record<string, JourneyState>;
}

// This could be a union type, but our logic makes heavy use of mutation which is easier on a single type
export interface JourneyState {
  parent?: string;
  journeyContext?: string;

  // For standard states
  response?: JourneyResponse;
  events?: Record<string, JourneyEvent>;

  // For nested states
  nestedJourney?: string;
  exitEvents?: Record<string, JourneyEvent>;

  // Synthetic states used for rendering nested journeys
  entryEvent?: string;
  exitEvent?: string;
}

// This could be a union type, but our logic makes heavy use of mutation which is easier on a single type
export interface JourneyResponse {
  // journeyTransition and nestedJourney are synthetic responses for rendering
  type:
    | "page"
    | "process"
    | "cri"
    | "error"
    | "journeyTransition"
    | "nestedJourney";

  // Page states
  pageId?: string;
  context?: string;

  // Process states
  lambda?: string;
  lambdaInput?: object;

  // CRI states
  criId?: string;

  // Error states
  statusCode?: number;

  // Synthetic response for rendering journey transitions
  targetJourney?: string;
  targetState?: string;

  // Synthetic response for rendering nested journeys
  nestedJourney?: string;
}

export interface JourneyEvent {
  targetState: string;
  targetJourney?: string;
  targetEntryEvent?: string;

  checkIfDisabled?: Record<string, JourneyEvent>;
  checkFeatureFlag?: Record<string, JourneyEvent>;
  checkJourneyContext?: Record<string, JourneyEvent>;
  checkMitigation?: Record<string, JourneyEvent>;

  exitEventToEmit?: string;

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
  nestedJourneyStates: Record<string, JourneyState>;
}
