package uk.gov.di.ipv.core.statemachine;

/**
 * The JourneyEngine is responsible for directing the flow of the user's journey through the IPV
 * system.
 *
 * Responses from the Journey engine, direct the Frontend to perform an action.
 *
 * These are:
 *  * `page`, display a particular page.
 *  * `journey`, run a new journey step against the journey engine.
 *  * `cri`, start a frontend cri journey to the specified cri.
 *  * `client`, return the user to the OAuth client with the given details.
 *
 *  In future the Journey engine will also know what active sessions the user has, and can direct
 *  the flow on a session by session basis. (How will we push an update to a session that the user
 *  is not directly updating. Would need some sort of websocket connection?)
 *
 */
public class JourneyEngine {

    private StateMachine stateMachine = new StateMachine(new StateMachineInitializer());

    public JourneyEngine(){

    }

    public JourneyStepResponse step(String userId, String journeyStep){

        // session = getUserSession()
        // state = session.getJourneyState()
        var state = "INIT";
        try {
            StateMachineResult resultState = stateMachine.transition(state, journeyStep, new Context());

            // the JourneyResponse we need here is quite tightly coupled to the state. Does it make any
            // sense to separate these out?

            // session.setJourneyState(resultState.getState());
            return resultState.getJourneyStepResponse();

        } catch (UnknownEventException e) {
            e.printStackTrace();
        }
        return null;
    }


}
