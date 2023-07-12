# Journey Engine

## Terms

### Journey Engine

The Journey Engine is what tells IPV Core Front what to show the user next. IPV Core Front calls the journey engine with `/journey/<journey-event>` requests to the internal API Gateway and the Journey Engine returns a Journey Response, that tells IPV Core front to show a page in IPV Core, redirect to a CRI, or a redirect to the originating OAuth client. 

(The Journey Engine can also tell IPV Core Front to fire a new Journey Event back to the Journey Engine, though this is being phased out.)

### Journey Engine Step Function

This is the AWS Step Function that orchestrates the running of the lambdas that make up the Journey Engine.

### Journey Engine State Machine

The Journey Engine State Machine is a custom build implementation of an event driven state machine. This transitions the user from one state to another when Journey Events are received. It is configured using a Journey Map

### Journey Map

The Journey Map defines what sates the user can be in, the events that those states accept and what states those events transition to. It also specifies what should happen during those transition. The Journey Map is the configuration of the Journey Engine State Machine and consists of a collection of Journey States.

### Nested Journey Map

To aid in building up a complex Journey Map, a smaller collection of Journey States can be referenced. This is a Nested Journey Map.

### Journey State

A Journey Sate represents a point in the user's journey. The definition includes the events that can be accepted when the user is in this state and what happens when that event is received.

### Journey Event

A Journey Event is a named event that has occurred in the users journey. IPV Core Front is responsible for interpreting the action a user has taken and turning it into an event that can be sent to the Journey Engine. The event is represented as a string in requests to the internal API Gateway `/journey/<journey-event>`

### Journey Response

A Journey Response is the JSON payload returned to IPV Core Front in response to call to the Journey Engine.

It can be one of 5 types:

* Page. Page responses tell IPV Core Front to display a page to the user. It is left to IPV Core to determine how best to render a "Page". The page response only specifies an identifier for the page. For example, IPV Core may decide to use the identifier to select between various dynamic components, or pick a particular piece of static content. Also a "Page" may be rendered to the user as a sequence of screens. This is all left to IPV Core Front.

* CRI. CRI responses tell IPV Core Front to redirect the user to a CRI. The response includes a properly constructed authorisation request for that CRI.

* Client. Client responses tell IPV Core Front to redirect the user to the OAuth client that initiated this identity proofing journey. The response includes a properly constructed redirect url that will be accepted by the client.

* Error. Error responses tell IPV Core Front that an error has has occurred in the Journey Engine. The response includes an HTTP error code that should be propagated to the user, and a page identifier for a page that should be shown to the user.

* Journey Event. Journey Event responses tell IPV Core Front that it should make another request to the Journey Engine with the specified event. This is a legacy response that has mostly been eliminated. This was previously used to orchestrate running multiple lambdas, but has been superseded by the Journey Engine Step Function.

### Journey Context

The Journey Context is a collection of data about the user's journey. Various components can access the journey context to read this data or update it. Data in the Journey Context can influence the Journey Path.

### Journey Path

The Journey Path is the sequence of States and events that the user has been on in this journey, a sequence of Journey Steps.

### Journey Step

A Journey Step is the transition from one Journey State to the next, triggered by a Journey Event. A sequence of Journey Steps makes up a Journey Path.




## How the Journey Engine works

The Journey Engine is what tells IPV Core Front what to show the user next. When the user does something, IPV Core Front figures out how to interpret that as an event and calls the journey engine with that event. The Journey Engine then returns a responds that tells IPV Core Front what to do.

It is up to core front how to interpret user actions like clicking a button, or selecting a particular radio option or collection of check boxes. Whatever the user has done, IPV Core Front should translate that into a single event and call the internal API Gateway with `/journey/<journey-event>`.

The `/journey/<journey-event>` route in the internal API Gateway is wired up to the Journey Engine Step Function. This is an AWS Step Function that handles orchestrating AWS Lambdas that make up the Journey Engine. The first lambda to be called is `process-journey-step` (this should be renamed `process-journey-event`). This lambda implements the Journey Engine State Machine. The Journey Engine State Machine 


(The Journey Engine can also tell IPV Core Front to fire a new Journey Event back to the Journey Engine, though this is being phased out.)


State STATE_NAME_1 {
    event-name-1 : { page: page-id, state: TARGET_STATE_NAME_1 }
    event-name-2: { cri: cri-id, state: TARGET_STATE_NAME_2 }
    event-name-3: { client: _, state: TARGET_STATE_NAME_3 }
    
}

State STATE_NAME

SATE_NAME -> event -> STATE_NAME

Event reusable_foo { page: page-id, state: TARGET_STATE_NAME_1 }

STATE:STATE_DEF -> event:event_def -> STATE -> event -> 



STATE_1 -> alpha -> STATE_A2 -> event -> STATE_3
                             -> event -> STATE
                             -> event -> STATE
                             -> event -> STATE
        -> bravo -> STATE_B3 -> event -> STATE_3
        -> charlie -> STATE_B3 -> event -> STATE_3
                                    
    
    
    - bar
    - wagga

How should the parsing of the state machine definition (journey map) work?

Parse the definition in to java objects.

JourneyMap is a collection of JourneyStates

JourneyState represents where the user is on their journey and where they can go to next
JourneyContext
JourneyEvent is recieved by a JourneyState???? Should we differentiate between the event and the deffinition of what to do when the event is recieved. YES

A Journey is a sequence of states and events. A Journey Step is sequence [JourneyState -> JourneyEvent -> JourneyState] and any side effects. 

A JourneyMaps can exist in a hierarchy where a JourneyState wraps a  is a 


A JourneyResponse is the result returned to the frontend.

The Journey Response from process-journey-step can be augmented. This is managed by the configuration of the Journey Engine Step Function. We should have a concept of Lambdas that run after the transition. We could also think about the process journey step having two parts, processing to set up the transition and a process to commit the transition?

JourneyEventHandler - JourneyTransitionHandler - CommitJourneyTransition

What are the parts of a journey transition?

There are 4 parts to processing a transition from one state to another in the journey engine.

1. pre-process: we run code before the state-machine.
2. handle-event: we figure out what the event should do.
3. post-processing: some code might need to be run to figure out what path to take.
4. commit-transition: This is the point that the store the new state and give a JournyResponse to the user.

We should be clear about what we are doing for every transition.

