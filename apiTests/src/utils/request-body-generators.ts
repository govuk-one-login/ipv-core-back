import {ProcessCriCallbackRequest} from "../interfaces/process-cri-callback-request.js";
import {CriStubResponse} from "../interfaces/cri-stub-response.js";
import {AuthRequestBody} from "../interfaces/auth-request-body.js";
import config from "../config.js";
import {generateJar} from "./jar-generator.js";

export const generateInitialiseIpvSessionBody = async (subject: string): Promise<AuthRequestBody> => {
   return {
       responseType: 'code',
       clientId: 'orchestrator',
       redirectUri: config.ORCHESTRATOR_REDIRECT_URI,
       state: 'api-tests-state',
       scope: 'openid',
       request: await generateJar(subject),
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
