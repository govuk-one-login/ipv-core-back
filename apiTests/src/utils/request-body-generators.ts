import {ProcessCriCallbackRequest} from "../interfaces/process-cri-callback-request.js";
import {CriStubResponse} from "../interfaces/cri-stub-response.js";
import {AuthRequestBody} from "../interfaces/auth-request-body.js";
import config from "../config.js";
import {generateJar} from "./jar-generator.js";
import path from "path";
import {fileURLToPath} from "url";
import fs from "node:fs";
import {getRandomString} from "./random-string-generator.js";
import {CriStubRequest} from "../interfaces/cri-stub-request.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
type JsonType = 'credentialSubject' | 'evidence'

export const generateInitialiseIpvSessionBody = async (subject: string, journeyType: string): Promise<AuthRequestBody> => {
   return {
       responseType: 'code',
       clientId: 'orchestrator',
       redirectUri: config.ORCHESTRATOR_REDIRECT_URI,
       state: 'api-tests-state',
       scope: 'openid',
       request: await generateJar(subject, journeyType),
   }
}

export const generateProcessCriCallbackBody = (criStubResponse: CriStubResponse): ProcessCriCallbackRequest => {
    const url = new URL(criStubResponse.redirectUri);
    const params = url.searchParams;
    const code = params.get('code');
    const state = params.get('state');
    const criId = params.get('id') || url.pathname.split('/')[3]
    if (!code || !state || !criId) {
        throw new Error(`Param missing from CRI callback redirect`, {cause: {code: code, state: state, criId: criId}})
    }
    return {
        authorizationCode: code,
        state: state,
        redirectUri: `${url.protocol}//${url.host}${url.pathname}`,
        credentialIssuerId: criId
    }
}

export const generateCriStubBody = (criId: string, scenario: string, redirectUrl: string): CriStubRequest => {
    const urlParams = new URL(redirectUrl).searchParams;
    return {
        clientId: urlParams.get('client_id') as string,
        request: urlParams.get('request') as string,
        credentialSubjectJson: readJsonFile(criId, scenario, 'credentialSubject'),
        evidenceJson: readJsonFile(criId, scenario, 'evidence'),
        resourceId: getRandomString(8),
    }
}

const readJsonFile = (criId: string, scenario: string, jsonType: JsonType) => {
   return JSON.stringify(JSON.parse(fs.readFileSync(path.join(__dirname, `../../data/cri-stub-requests/${criId}/${scenario}/${jsonType}.json`), 'utf8')));
}
