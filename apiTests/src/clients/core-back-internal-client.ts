import config from '../config.js'
import {JourneyEngineResponse} from "../interfaces/journey-engine-response.js";
import {ProcessCriCallbackRequest} from "../interfaces/process-cri-callback-request.js";
import {ProcessCriCallbackResponse} from "../interfaces/process-cri-callback-response.js";
import {AuthRequestBody} from "../interfaces/auth-request-body.js";

const JOURNEY_PREFIX: string = '/journey/'
const POST: string = 'POST'

export const initialiseIpvSession = async (requestBody: AuthRequestBody): Promise<string> => {
    const response = await fetch(config.CORE_BACK_INTERNAL_API_URL + '/session/initialise', {
        method: 'POST',
        headers: internalApiHeaders,
        body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
        throw new Error("InitialiseIpvSession request failed: " + response.statusText)
    }
    const responseBody = await response.json();

    return responseBody.ipvSessionId as string;
}

export const sendJourneyEvent = async (event: string, ipvSessionId: string): Promise<JourneyEngineResponse> => {
    const url = config.CORE_BACK_INTERNAL_API_URL + (event.startsWith(JOURNEY_PREFIX) ? event : JOURNEY_PREFIX + event);
    const response = await fetch(url, {
        method: POST,
        headers: { ...internalApiHeaders, ...{'ipv-session-id': ipvSessionId} },
    })

    if (!response.ok) {
        throw new Error("sendJourneyEvent request failed: " + response.statusText)
    }

    return await response.json() as JourneyEngineResponse;
}

export const processCriCallback = async (requestBody: ProcessCriCallbackRequest, ipvSessionId: string): Promise<ProcessCriCallbackResponse> => {
    const response = await fetch(config.CORE_BACK_INTERNAL_API_URL + '/cri/callback', {
        method: POST,
        headers: { ...internalApiHeaders, ...{'ipv-session-id': ipvSessionId} },
        body:JSON.stringify(requestBody),
    })

    if (!response.ok) {
        throw new Error("sendJourneyEvent request failed: " + response.statusText)
    }

    return await response.json();
}

const internalApiHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-api-key': config.CORE_BACK_INTERNAL_API_KEY,
    'ip-address': 'unknown',
}
