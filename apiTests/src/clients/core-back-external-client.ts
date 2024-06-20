import {createSignedJwt} from "../utils/jwt-signer.js";
import config from "../config.js";
import {TokenResponse} from "../interfaces/token-response.js";

const ORCHESTRATOR_CLIENT_ID = 'orchestrator'

export const exchangeCodeForToken = async (redirectUrl: string): Promise<TokenResponse> => {
    const code = new URL(redirectUrl).searchParams.get("code");
    if (!code) {
        throw new Error("code not received in redirect URL")
    }

    const privateKeyJwt = await createSignedJwt({sub: ORCHESTRATOR_CLIENT_ID, iss: ORCHESTRATOR_CLIENT_ID});
    const requestBody = `grant_type=authorization_code&` +
        `code=${code}&` +
        `redirect_uri=${encodeURI(config.ORCHESTRATOR_REDIRECT_URI)}&` +
        `client_id=${ORCHESTRATOR_CLIENT_ID}&` +
        `client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&` +
        `client_assertion=${privateKeyJwt}`

    const response = await fetch(config.CORE_BACK_EXTERNAL_API_URL + '/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: requestBody
    });

    if (!response.ok) {
        throw new Error("exchangeCodeForToken request failed: " + response.statusText)
    }

    return await response.json()
}

export const getIdentity = async (tokenResponse: TokenResponse): Promise<any> => {
    const response = await fetch(config.CORE_BACK_EXTERNAL_API_URL + `/user-identity`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${tokenResponse.access_token}`
        }
    });

    if (!response.ok) {
        console.log(response)
        throw new Error("getIdentity request failed: " + response.statusText)
    }

    return await response.json()
}
