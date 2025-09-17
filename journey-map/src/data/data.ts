export interface JourneyTransition {
  fromJourney: string;
  from: string;
  toJourney: string;
  to: string;
  count: number;
}

let journeyTransitions: JourneyTransition[] = [];

export const getJourneyTransitionsData = (): JourneyTransition[] => {
  return journeyTransitions;
};

export const setJourneyTransitionsData = (
  newJourneyTransitions: JourneyTransition[],
): void => {
  journeyTransitions = newJourneyTransitions;
};
