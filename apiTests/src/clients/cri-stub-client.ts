import fs from "node:fs";
import path from "path";
import {RedirectParams} from "../interfaces/redirect-params.js";
import {fileURLToPath} from "url";
import {ProcessCriCallbackRequest} from "../interfaces/process-cri-callback-request.js";
import {CriStubResponse} from "../interfaces/cri-stub-response.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const callHeadlessApi = async (redirectUrl: string, criStubData: string): Promise<CriStubResponse> => {
    const payloadData = JSON.parse(fs.readFileSync(path.join(__dirname, `../../data/cri-stub-requests/${criStubData}.json`), 'utf8'));
    const payload = {
        ...payloadData,
        ...extractParamsFromRedirectUrl(redirectUrl)
    }
    const criStubResponse = await fetch(new URL(redirectUrl).origin + '/api/authorize', {
        method: 'POST',
        body: JSON.stringify(payload),
        redirect: 'manual'
    });

    if (!(criStubResponse.status === 302)) {
        throw new Error("callHeadlessApi request failed: " + criStubResponse.statusText)
    }

    return {
        redirectUri: criStubResponse.headers.get('location') as string
    }
}

const extractParamsFromRedirectUrl = (redirectUrl: string): RedirectParams => {
    const params = new URL(redirectUrl).searchParams;
    return {
        clientId: params.get('client_id'),
        request: params.get('request'),
    }
}
