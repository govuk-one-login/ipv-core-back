import * as assert from 'assert';
import {Then, When} from '@cucumber/cucumber';
import {World} from '../../src/interfaces/world.js'
import * as internalClient from '../../src/clients/core-back-internal-client.js'
import * as externalClient from '../../src/clients/core-back-external-client.js'
import * as criStubClient from '../../src/clients/cri-stub-client.js'
import config from "../../src/config.js";
import {generateProcessCriCallbackBody} from "../../src/utils/request-body-generators.js";

When('I start a new identity journey', async function (this: World): Promise<void> {
    const sessionInitResponse = await internalClient.initialiseIpvSession();
    this.userId = sessionInitResponse.userId;
    this.ipvSessionId = sessionInitResponse.ipvSessionId;
    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent('/journey/next', this.ipvSessionId);
});

Then('I get a(n) {string} page response', function(this: World, expectedPage: string): void {
    assert.equal(expectedPage, this.lastJourneyEngineResponse.page);
})

When('I submit a(n) {string} event', async function(this: World, event: string): Promise<void> {
    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(event, this.ipvSessionId)
})

Then('I get a(n) {string} CRI response', function(this: World, expectedCri: string): void {
    assert.equal(expectedCri, this.lastJourneyEngineResponse.cri.id);
})

When('I submit {string} details to the CRI stub', async function(this: World, criStubData: string): Promise<void> {
    const criStubResponse = await criStubClient.callHeadlessApi(this.lastJourneyEngineResponse.cri.redirectUrl, criStubData);
    const processCriCallbackRequestBody = generateProcessCriCallbackBody(criStubResponse);
    const journeyResponse = await internalClient.processCriCallback(processCriCallbackRequestBody, this.ipvSessionId);
    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(journeyResponse.journey, this.ipvSessionId);
})

Then('I get a client Oauth response', function(this: World): void {
    const url = new URL(this.lastJourneyEngineResponse.client.redirectUrl);
    assert.equal(config.ORCHESTRATOR_REDIRECT_URI, `${url.protocol}//${url.host}${url.pathname}`)
})

When('I use the Oauth response to get my identity', async function(this: World): Promise<void> {
    const tokenResponse = await externalClient.exchangeCodeForToken(this.lastJourneyEngineResponse.client.redirectUrl);
    this.identity = await externalClient.getIdentity(tokenResponse);
})

Then('I get a {string} identity', function(this: World, vot: string): void {
    assert.equal('P2', this.identity.vot)
})
