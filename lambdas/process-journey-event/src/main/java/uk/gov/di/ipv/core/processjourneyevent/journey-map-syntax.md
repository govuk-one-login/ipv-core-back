# The Journey Map
The Journey Map defines what states the user can be in, the events that those states accept and what states those events transition to.
It also specifies what should happen during those transitions. The Journey Map is the configuration of the Journey Engine State Machine and consists of a collection of Journey States.

The Journey Map consists of `sub-journeys` which represent unique user journeys and `nested journeys` which are common user flows used one or more times within various sub-journeys.

[Sub-journeys](#top-level-structure-of-sub-journeys) are stored alongside each other under [`/resources/statemachine/journey-maps`](https://github.com/govuk-one-login/ipv-core-back/tree/main/lambdas/process-journey-event/src/main/resources/statemachine/journey-maps).

[Nested journeys](#nested-journeys) are stored in [`/resources/statemachine/journey-maps/nested-journey`](https://github.com/govuk-one-login/ipv-core-back/tree/main/lambdas/process-journey-event/src/main/resources/statemachine/journey-maps/nested-journeys).

## Top-level structure of sub-journeys
Each sub-journey map file starts with a `name`, `description` and `states` field:
```yaml
name: New Identity
description: The journey for new identities

states:
  ... # here, we define a list of states a user can be in
```

## Sub-Journey State
A basic state has a name, a list of `events` that state accepts and optionally, a `response` type.
```yaml
BASIC_STATE_NAME:
  response:
    type: process
    lambda: reset-session-identity
  events:
    event_name_1:
      ...
    event_name_2:
      ...
```

### Sub-Journey Entry Point State
A state can be used as an entry point to another sub-journey if the `response` is omitted. To enter a new sub-journey, we must specify the `targetJourney` and `targetState` on the event:
```yaml
# In initial-journey.yaml
name: Initial Journey
description: The initial journey for users before creating new identities

states:
    BASIC_STATE_NAME:
      response:
        type: page
        pageId: live-in-uk
      events:
        next:
          targetJourney: NEW_IDENTITY
          targetState: ENTRY_POINT_STATE_NAME
```

```yaml
# In sub-journey.yaml
name: New Identity
description: The journey for creating new identities

states:
    ENTRY_POINT_STATE_NAME:
      events:
        event_name_1:
          ...
        event_name_2:
          ...
```

### Nested Journey Entry State
A state can also act as the entry-way for a nested journey by omitting the `response` and adding a `nestedJourney` identifier.
Rather than `event`, these accept `exitEvents` emitted by the nested journey. The exit events have the same shape as a basic [Event](#events).
```yaml
NESTED_JOURNEY_STATE_NAME:
  nestedJourney: WEB_DL_OR_PASSPORT # the name of the nested journey to enter
  exitEvents: # all the exit events emitted by the nested journey
    exitEvent1:
      ...
    exitEvent2:
      ...
```

All exit events specified in the Nested Journey Entry State must cover all exit events from the [Nested Journey](#nested-journeys).

## Response Types
The `response` defines the Step Response type returned by the State Machine when transitioning to this state. A `response` can be three types:
* `process`: the state represents a lambda
* `page`: the state represents a page
* `cri`: the state represents a CRI
```yaml
PROCESS_STATE:
  response:
    type: process
    lambda: process-candidate-identity # this is the name of the lambda
    lambdaInput: # define all inputs to the lambda here
      identityType: NEW
  events:
    ...

PAGE_STATE:
  response:
    type: page
    pageId: live-in-uk # this is the page ID defined in core-front
  events:
    ...

CRI_STATE:
  response:
    type: cri
    criId: dcmaw
  events:
    ...
```

## Events
The `events` define what the state accepts and how the State Machine should handle it. Events have the following options:

**Target state options:**
* `targetState`: the State name to transition to following the event
* `targetJourney`: the name of the sub-journey to route to. This must be accompanied by a valid `targetState` which points to an entry state within the `targetJourney`.
* `targetEntryEvent`: if transitioning to a [Nested Journey Entry State](#nested-journey-entry-state), this specifies the nested journey entry event

**Journey context options:**
* `journeyContextToSet`: adds a context to the existing Journey Contexts when the given event is emitted
* `journeyContextToUnset`: removes a context from the existing Journey Contexts when the given event is emitted

**Conditional handling options:**
* `checkIfDisabled`: defines next state if a given CRI is disabled
* `checkFeatureFlag`: defines the next state if a feature flag is enabled
* `checkMitigation`: defines the next state if a mitigation is applicable for the user
* `checkJourneyContext`: defines the next state if a journey context exists in the current list of journey contexts

> **Journey Contexts**: A list of journey contexts is stored on the IPV session item which is used for further refining the routing depending on the user's journey e.g. if they are a non-UK resident.

Examples of the various options allowed with events:
```yaml
STATE_WITH_DISABLED_CRI_CONDITION:
  response:
    type: process
    lambda: reset-session-identity
  events:
    next: # this is the event name
      targetState: STATE_2 # if the reset-session-identity lambda emits a "next" event, the State Machine will transition to "STATE_2"
      journeyContextToSet: fraudCheck # the journey context to add to the existing journey contexts
      journeyContextToUnset: internationalAddress # the journey context to remove from the existing journey contexts
      checkIfDisabled:
        dcmaw: # this is the CRI ID
          targetState: STATE_3 # if the DCMAW CRI is disabled, when a "next" event is emitted, the State Machine will transition to "STATE_3" instead of "STATE_2"

STATE_WITH_FEATURE_FLAG_CONDITION:
  response:
    type: page
    pageId: live-in-uk
  events:
    next:
      targetState: STATE_2 # if the State Machine receives a "next" event, the State Machine will transition to "STATE_2"
      checkFeatureFlag:
        strategicAppEnabled: # this is the feature flag we want to check
          targetState: STATE_3 # if a "next" event is received and the "strategicAppEnabled" feature flag is enabled, the State Machine will transition to "STATE_3" instead of "STATE_2"

STATE_WITH_JOURNEY_CONTEXT_CONDITION:
  response:
    type: cri
    criId: DCMAW
  events:
    next:
      targetState: STATE_2 # if the State Machine receives a "next" event, the State Machine will transition to "STATE_2"
      checkJourneyContext:
        internationalAddress: # this is the journey context we want to check
          targetState: STATE_3 # if a "next" event is received and there is a "internationalAddress" journey context stored in the session, the State Machine will transition to "STATE_3" instead of "STATE_2"

STATE_WITH_MITIGATION_CONDITION:
  response:
    type: cri
    criId: DCMAW
  events:
    next:
      targetState: STATE_2 # if the State Machine receives a "next" event, the State Machine will transition to "STATE_2"
      checkMitigation:
        invalid-doc: # this is the mitigation we want to check
          targetState: STATE_3 # if a "next" event is received and the user had a valid "invalid-doc" mitigation, the State Machine will transition to "STATE_3" instead of "STATE_2"
```
Since each of the conditional handling options above accepts an `event` object, it's possible to nest these different options for finer routing from a state.

Note that there is a priority order in which the conditional checks are evaluated. If a set of conditional checks are on the same level, the order of evaluation is:
1. checkIfDisabled
2. checkJourneyContext
3. checkFeatureFlag
4. checkMitigation

Taking the below yaml as an example, `checkIfDisabled` is evaluated first regardless of the order they are defined in the state.
This means that if `dcmaw` is disabled, the State Machine will transition to the `A_NEW_JOURNEY` state even if an `invalid-dl` mitigation is applicable.

```yaml
STATE_1:
  response:
    type: process
    lambda: reset-session-identity
  events:
    next:
      targetState: STATE_2 # if the reset-session-identity lambda emits a "next" event, the State Machine will transition to "STATE_2" by default
      checkMitigation:
        invalid-dl:
          targetJourney: MITIGATION_STATE # if "invalid-dl" is an applicable mitigation AND "dcmaw" is enabled, the State Machine will transition to MITIGATION_STATE, unless the "someFeatureFlag" is enabled which will route to the "ANOTHER_STATE" state
          checkFeatureFlag:
            someFeatureFlag:
              targetJourney: ANOTHER_STATE
      checkIfDisabled:
        dcmaw: # this is the CRI ID
          targetState: A_NEW_JOURNEY # if the DCMAW CRI is disabled, REGARDLESS of whether "invalid-dl" mitigation is applicable, when a "next" event is emitted, the State Machine will transition to "STATE_3" instead of "STATE_2"
```

### Adding Audit Events to an Event
It's possible to emit an audit event if the Journey Engine receives a particular event at a specific state.
```yaml
STATE_WITH_AUDIT_EVENT:
  response:
    type: process
    lambda: reset-session-identity
  events:
    next:
      targetState: STATE_2
      auditEvents:
        - IPV_RESET_IDENTITY # This is the name of the audit event
      auditContext: # Use this to specify additions to the audit event e.g. custom extensions configured within the `process-journey-event` lambda
        mitigationType: enhanced-verification
```

If not specifying an `auditContext`, by default, `process-journey-event` will emit audit events with the names listed under `auditEvents` containing `deviceInformation` and a `users` block.
To add custom properties to the audit event e.g. extensions, pass in an `auditContext` and update `process-candidate-identity` to handle the context appropriately.

## Nested Journeys
The nested journeys define common user flows that can be used one or more times within various sub-journeys.

Nested journeys require a `name`, `description`, a list of `entryEvents` and a list of `nestedJourneyStates`:
```yaml
name: Nested Journey Name
description: Description of the nested journey

entryEvents:
  entryEvent1: # Target entry events follow the same shape as events
    targetState: STATE_1
  entryEvent2:
    targetState: STATE_2
    checkFeatureFlag:
      someFeatureFlag:
        ...

nestedJourneyStates:  # Nested journey states follow the same shape as states within a sub journey
  STATE_1:
    response:
      type: cri
      criId: ukPassport
    events:
      next:
        targetState: STATE_2
      error:
        exitEventToEmit: error # This is specific to nested journey events
```

### Nested journey events: exitEventToEmit
Nested journey events have the same options as [events](#events) in sub-journeys as well as an `exitEventToEmit` which maps to an exit event defined in [Nested Journey Entry States](#nested-journey-entry-state).
