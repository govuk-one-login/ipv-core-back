import config from '../config.js'
import {SessionInitResponse} from "../interfaces/session-init-response.js";
import {getRandomString} from "../utils/random-string-generator.js";
import {JourneyEngineResponse} from "../interfaces/journey-engine-response.js";
import {ProcessCriCallbackRequest} from "../interfaces/process-cri-callback-request.js";
import {ProcessCriCallbackResponse} from "../interfaces/process-cri-callback-response.js";
import {generateInitialiseIpvSessionBody} from "../utils/request-body-generators.js";

const JOURNEY_PREFIX: string = '/journey/'
const POST: string = 'POST'

export const initialiseIpvSession = async (): Promise<SessionInitResponse> => {
    const subject = getRandomString(16);
    let response
    try {
        response = await fetch(config.CORE_BACK_INTERNAL_API_URL + '/session/initialise', {
            method: 'POST',
            headers: internalApiHeaders,
            body: JSON.stringify(await generateInitialiseIpvSessionBody(subject)),
        });
    } catch (error) {
        console.log(error)
        throw error
    }

    if (!response.ok) {
        throw new Error("InitialiseIpvSession request failed: " + response.statusText)
    }
    const responseBody = await response.json();

    return {
        ipvSessionId: responseBody.ipvSessionId as string,
        userId: subject
    };
}

export const sendJourneyEvent = async (event: string, ipvSessionId: string): Promise<JourneyEngineResponse> => {
    const headers = { ...internalApiHeaders, ...{'ipv-session-id': ipvSessionId} };
    const url = config.CORE_BACK_INTERNAL_API_URL + (event.startsWith(JOURNEY_PREFIX) ? event : JOURNEY_PREFIX + event);
    const response = await fetch(url, {
        method: POST,
        headers: headers,
    })

    if (!response.ok) {
        throw new Error("sendJourneyEvent request failed: " + response.statusText)
    }

    return await response.json() as JourneyEngineResponse;
}

export const processCriCallback = async (requestBody: ProcessCriCallbackRequest, ipvSessionId: string): Promise<ProcessCriCallbackResponse> => {
    const headers = { ...internalApiHeaders, ...{'ipv-session-id': ipvSessionId} };
    const response = await fetch(config.CORE_BACK_INTERNAL_API_URL + '/cri/callback', {
        method: POST,
        headers: headers,
        body:JSON.stringify(requestBody),
    })

    if (!response.ok) {
        console.log(response)
        throw new Error("sendJourneyEvent request failed: " + response.statusText)
    }

    return await response.json();
}

const internalApiHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-api-key': config.CORE_BACK_INTERNAL_API_KEY,
    'ip-address': 'unknown',
}
