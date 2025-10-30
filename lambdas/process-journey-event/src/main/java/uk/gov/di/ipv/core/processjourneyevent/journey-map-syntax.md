# The Journey Map
The Journey Map defines what states the user can be in, the events that those states accept and what states those events transition to.
It also specifies what should happen during those transitions. The Journey Map configures the accepted states and transitions for the State Machine.

The Journey Map consists of `sub-journeys` which represent unique user journeys and `nested journeys` which are common user flows used one or more times within the sub-journeys.

[Sub-journeys](#top-level-structure-of-sub-journeys) are stored alongside each other under [`/resources/statemachine/journey-maps`](https://github.com/govuk-one-login/ipv-core-back/tree/main/lambdas/process-journey-event/src/main/resources/statemachine/journey-maps).

[Nested journeys](#nested-journeys) are stored within [`/resources/statemachine/journey-maps/nested-journey`](https://github.com/govuk-one-login/ipv-core-back/tree/main/lambdas/process-journey-event/src/main/resources/statemachine/journey-maps/nested-journeys).

## Top-level structure of Sub-Journeys
Each sub-journey map file starts with a `name`, `description` and `states` field:
```yaml
name: New Identity
description: The journey for new identities

states:
  ... # here, we define a list of states a user can be in
```

## Sub-Journey States
Journey States represent a point in the user's journey.
A basic state is defined by a name, a list of `events` that state accepts and optionally, a `response` type.
```yaml
BASIC_STATE_NAME:
  response: # This defines the Step Response from the State Machine when transitioning to this state
    type: process
    lambda: reset-session-identity
  events:
    event_name_1: # These are the events the state supports, which define what will happen if the event is received from this state
      ...
    event_name_2:
      ...
```

### Sub-Journey Entry Point State
A state can be used as an entry point to another sub-journey if the `response` is omitted. To enter a new sub-journey, we must specify the `targetJourney` and `targetState` on the event:
```yaml
# In the initial-journey.yaml sub-journey
name: Initial Journey
description: The initial journey for users before creating new identities

states:
    BASIC_STATE_NAME:
      response:
        type: page
        pageId: live-in-uk
      events:
        next:
          targetJourney: NEW_IDENTITY # the name of the sub-journey
          targetState: ENTRY_POINT_STATE_NAME # the name of the state acting as an entry-state
```

```yaml
# In the new-identity.yaml sub-journey
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

### State Inheritance
It is also possible to define a common state for other states to inherit from. These also omit the `response` type and a `parent` must be defined within the state.

When a child state inherits from a parent state, it inherits all the events from the parent state without having to explicitly define the same events.
It can also override any events specified in the parent state.

```yaml
# In the new-identity.yaml sub-journey
name: New Identity
description: The journey for creating new identities

states:
    PARENT_STATE:
      events:
        access_denied:
          ...
        server_error:
          ...

    CHILD_STATE: # <- Even though the CHILD_STATE doesn't explicitly define the same events, it can accept all the events from the PARENT_STATE
      response:
        type: cri
        criId: dcmaw
      parent: PARENT_STATE # define parent state here
      events:
        next:
          ...
        server_error: # This will override the "server_error" event defined in the PARENT_STATE
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

All exit events specified on a nested journey entry state must cover all exit events emitted from the [Nested Journey](#nested-journeys).

## Response Types
The Step Response returned by the State Machine when transitioning to this state is reflected by the `response` block. A `response` can be three types:
* `process`: the state represents a lambda
* `page`: the state represents a page
* `cri`: the state represents a CRI
```yaml
PROCESS_STATE:
  response:
    type: process
    lambda: process-candidate-identity # this is the name of the lambda
    lambdaInput: # this optional field defines all inputs to the lambda
      identityType: NEW
  events:
    ...

PAGE_STATE:
  response:
    type: page
    pageId: live-in-uk # this is the page identifier defined in core-front
    context: fraud # this optional field tells IPV Core Front to display a variant of a dynamic page
  events:
    ...

CRI_STATE:
  response:
    type: cri
    criId: dcmaw # this is the CRI identifier
  events:
    ...
```

## Events
The `events` define what the state accepts and how the State Machine should handle when it receives a particular event for the current state.

> The listed `events` must cover all of the events that could possibly be emitted by the state.

Events have the following options:

**Target state options:**
* `targetState`: the State name to transition to following the State Machine receiving the event.
* `targetJourney`: the name of the sub-journey to route to. This must be accompanied by a valid `targetState` which points to an entry state within the `targetJourney`.
* `targetEntryEvent`: if transitioning to a [Nested Journey Entry State](#nested-journey-entry-state), this specifies which of the entry events defined in the [Nested Journey](#nested-journeys) to transition to.
If not specified, by default, the entry event used will be the same as the event received by the State Machine.

**Journey context options:**
* `journeyContextToSet`: adds a context to the existing Journey Contexts list when a given event is received
* `journeyContextToUnset`: removes a context from the existing Journey Contexts list when a given event is received

**Conditional handling options:**
* `checkIfDisabled`: defines next state if a given CRI is disabled
* `checkFeatureFlag`: defines the next state if a feature flag is enabled
* `checkMitigation`: defines the next state if a mitigation is applicable for the user
* `checkJourneyContext`: defines the next state if a matching context exists in the current list of journey contexts

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
      journeyContextToSet: fraudCheck # this adds "fraudCheck" to the Journey Contexts if the next state is STATE_2
      journeyContextToUnset: internationalAddress # this removes "internationalAddress" from the Journey Contexts if the next state is STATE_2
      checkIfDisabled:
        dcmaw: # this is the CRI ID
          targetState: STATE_3 # if the DCMAW CRI is disabled, when a "next" event is emitted, the State Machine will transition to "STATE_3" instead of "STATE_2". The journey context changes above do not apply.

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
          targetState: STATE_3 # if a "next" event is received and there is an "internationalAddress" journey context stored in the session, the State Machine will transition to "STATE_3" instead of "STATE_2"

STATE_WITH_MITIGATION_CONDITION:
  response:
    type: cri
    criId: DCMAW
  events:
    next:
      targetState: STATE_2 # if the State Machine receives a "next" event, the State Machine will transition to "STATE_2"
      checkMitigation:
        invalid-doc: # this is the mitigation we want to check
          targetState: STATE_3 # if a "next" event is received and the user has an "invalid-doc" mitigation, the State Machine will transition to "STATE_3" instead of "STATE_2"
```
Since each of the conditional handling options above accepts an `event` object, it's possible to nest these different options for finer routing.

Note that there is a priority order in which the conditional checks are evaluated. If a set of conditional checks are on the same level, the order of evaluation is:
1. checkIfDisabled
2. checkJourneyContext
3. checkFeatureFlag
4. checkMitigation

Taking the below yaml as an example, `checkIfDisabled` is evaluated first regardless of the order the conditional checks are defined in.
This means that if the `dcmaw` CRI is disabled, the State Machine will transition to the `A_NEW_JOURNEY` state even if an `invalid-dl` mitigation is applicable.

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
          targetJourney: MITIGATION_STATE # if "invalid-dl" is an applicable mitigation AND "dcmaw" is enabled, the State Machine will transition to MITIGATION_STATE
          checkFeatureFlag:
            someFeatureFlag:
              targetJourney: ANOTHER_STATE # if "invalid-dl" is an applicable mitigation AND "dcmaw" is enabled AND the "someFeatureFlag" is enabled, the State Machine will route to "ANOTHER_STATE"
      checkIfDisabled:
        dcmaw:
          targetState: A_NEW_JOURNEY # if the DCMAW CRI is disabled, REGARDLESS of whether "invalid-dl" mitigation is applicable, when a "next" event is emitted, the State Machine will transition to "STATE_3" instead of "STATE_2"
```

### Emitting Audit Events When Receiving An Event
It's possible to emit an audit event if the Journey Engine receives a particular event at a given state.
```yaml
STATE_WITH_AUDIT_EVENT:
  response:
    type: process
    lambda: reset-session-identity
  events:
    next:
      targetState: STATE_2
      auditEvents: # Here, we can specify a list of audit event names
        - IPV_RESET_IDENTITY
      auditContext: # Use this to specify additions to the audit event e.g. custom extensions configured within the `process-journey-event` lambda
        mitigationType: enhanced-verification
```

If not specifying an `auditContext`, by default, `process-journey-event` will emit audit events with the names listed under `auditEvents` containing `deviceInformation` and a `users` block.
To add custom properties to the audit event e.g. extensions, pass in an `auditContext` and update `process-journey-event` to handle the context appropriately.

## Nested Journeys
The nested journeys define common user flows that can be used one or more times within the sub-journeys.

At a top-level, nested journeys require a `name`, `description`, a list of `entryEvents` and a list of `nestedJourneyStates`.

Nested journey states have the same shape as sub-journey states but the events block consists of Nested Journey Events.

Nested journey events have the same properties as [events](#events) as well as an `exitEventToEmit`.
This is similar to `targetState` but instead of taking a state name, it takes an exit event name which maps to an exit event defined in [nested journey entry states](#nested-journey-entry-state).
These are exit points out of the nested journey.

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
        checkMitigation:
          invalid-dl:
            exitEventToEmit: invalid-dl
            checkIfDisabled:
              dcmaw:
                targetState: STATE_3
      error:
        exitEventToEmit: error # This is specific to nested journey events and maps to an exit event defined in nested journey entry states
        checkFeatureFlag:
          fraudCheck:
            targetState: STATE_4
```
