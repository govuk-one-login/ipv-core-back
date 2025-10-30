# The Journey Engine

The Journey Engine is responsible for deciding where to route the user based on their current state and the event passed to it.

IPV Core Front calls the journey engine with /journey/<journey-event> requests to the internal API Gateway and the Journey Engine returns a Journey Response, that tells IPV Core front to show a page in IPV Core, redirect to a CRI, or a redirect to the originating OAuth client.

## Journey Engine Lambdas and the State Machine
The lambdas which comprise the journey engine is orchestrated by an AWS Step Function (the `JourneyEngineStepFunction`) and is triggered by core-front calling the `/journey/{event}` endpoint on the Internal API.

| Journey Engine Lambda           | Trigger                                     | Description                                                                                                                                                                                                                                                                             |
|---------------------------------|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `process-journey-event`         | Any call to the `/journey/{event}` endpoint | The first lambda to be called within the Journey Engine, it runs the `Journey Engine State Machine` code responsible for transitioning the user from one state to another in the `Journey Map`. This lambda returns a Step Response.                                                    |
| `check-existing-identity`       | `/journey/check-existing-identity`          | Called at the beginning of a user's identity proofing journey, this lambda returns a `/journey/{event}` depending on their current identity status, account intervention and possible mitigations.                                                                                      |
| `reset-session-identity`        | `/journey/reset-session-identity`           | Resets a set or all of a user's VCs from the sessions credential store based on the input to the lambda. Can only reinstate a user's VCs from EVCS.                                                                                                                                     |
| `build-cri-oauth-request`       | `/journey/cri/build-oauth-request`          | Called when `process-journey-event` returns a CRI step response. This lambda builds the CRI oauth request which is returned to core-front for redirection.                                                                                                                              |
| `check-gpg45-score`             | `/journey/check-gpg45-score`                | Calculates the GPG45 scores from a user's current set of VCs and returns whether the score from `scoreType` meets the `scoreThreshold`. This returns a `/journey/{event}`.                                                                                                              |
| `call-dcmaw-async-cri`          | `/journey/call-dcmaw-async-cri`             | Starts a session with the DCMAW Async CRI. Returns a `/journey/{event}`.                                                                                                                                                                                                                |
| `check-reverification-identity` | `/journey/check-reverification-identity`    | Called at the start of a reverification journey, this lambda checks to see if a user has an existing identity and returns `/journey/{event}` based on the results.                                                                                                                      |
| `process-candidate-identity`    | `/journey/process-candidate-identity`       | Called at the end of every user journey, this lambda runs COI checks, evaluates the user's GPG45 score, calls TICF, persists the user's VCs to EVCS and/or creates a stored identity based on the user's journey. Results inform the event returned in the `/journey/{event}` response. |

A full flow of the Journey Engine Step Function can be found in [here](https://github.com/govuk-one-login/ipv-core-back/blob/main/deploy/journeyEngineStepFunction.asl.json).

### Step Response
A Step Response is the output from transitioning to a new state. It is defined on each state in the journey map, and will be the output of the `process-journey-event` lambda after the state transition. This can either be used by the state machine internally, or returned to IPV Core Front as a Journey Response (see below). The process-journey-event lambda output (a Step Response), will be checked by the Journey Engine Step Function. The step function may use it to invoke another lambda, or may decide to return it to core front. There are currently 4 types:

Page step response. This will be returned by the step function to core front as a Page Journey Response.
Error step response. This is effectively a page response but includes a status code. This will be returned to core front as an Error Journey Response
Journey step response. This will be used by the step function to invoke another lambda.
Cri step response. This is a special type of journey step response. It exists to allow the CRI ID to be easily passed to the build-cri-oauth-request lambda.
Process step response. This is configured with a lambda and some input data. It will cause the lambda to be invoked and passed the data. The lambda should return an event.

### Journey Response
A Journey Response is the JSON payload returned to IPV Core Front in response to call to the Journey Engine.

It can be one of 5 types:

* Page: Page responses tell IPV Core Front to display a page to the user. It is left to IPV Core to determine how best to render a "Page". The page response only specifies an identifier for the page. For example, IPV Core may decide to use the identifier to select between various dynamic components, or pick a particular piece of static content. Also, a "Page" may be rendered to the user as a sequence of screens. This is all left to IPV Core Front.
* CRI: CRI responses tell IPV Core Front to redirect the user to a CRI. The response includes a properly constructed authorisation request for that CRI.
* Client: Client responses tell IPV Core Front to redirect the user to the OAuth client that initiated this identity proofing journey. The response includes a properly constructed redirect url that will be accepted by the client.
* Error: Error responses tell IPV Core Front that an error has occurred in the Journey Engine. The response includes an HTTP error code that should be propagated to the user, and a page identifier for a page that should be shown to the user.
* Journey Event: Journey Event responses tell IPV Core Front that it should make another request to the Journey Engine with the specified event. This is a legacy response that has mostly been eliminated. This was previously used to orchestrate running multiple lambdas, but has been superseded by the Journey Engine Step Function.

## The Journey Map
The Journey Map defines what states the user can be in, the events that those states accept and what states those events transition to.
It also specifies what should happen during those transitions. The Journey Map is the configuration of the Journey Engine State Machine and consists of a collection of Journey States.

The Journey Map consists of `sub-journeys` which represent unique user journeys and `nested journeys` which are common user flows used one or more times within various sub-journeys.

For more information on the journey map and its syntax, see [here](journey-map-syntax.md).
