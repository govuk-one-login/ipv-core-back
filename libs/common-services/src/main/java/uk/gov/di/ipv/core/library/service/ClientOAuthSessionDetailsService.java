package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;

import java.text.ParseException;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CLIENT_OAUTH_SESSIONS_TABLE_NAME;

public class ClientOAuthSessionDetailsService {
    private final DataStore<ClientOAuthSessionItem> dataStore;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public ClientOAuthSessionDetailsService(ConfigService configService) {
        this.configService = configService;
        dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(CLIENT_OAUTH_SESSIONS_TABLE_NAME),
                        ClientOAuthSessionItem.class,
                        DataStore.getClient(),
                        configService);
    }

    public ClientOAuthSessionDetailsService(
            DataStore<ClientOAuthSessionItem> dataStore, ConfigService configService) {
        this.dataStore = dataStore;
        this.configService = configService;
    }

    public ClientOAuthSessionItem getClientOAuthSession(String clientOAuthSessionId) {
        return dataStore.getItem(clientOAuthSessionId);
    }

    public ClientOAuthSessionItem generateClientSessionDetails(
            String clientOauthSessionId,
            JWTClaimsSet claimsSet,
            String clientId,
            String evcsAccessToken)
            throws ParseException {
        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();

        clientOAuthSessionItem.setClientOAuthSessionId(clientOauthSessionId);
        clientOAuthSessionItem.setResponseType(claimsSet.getStringClaim("response_type"));
        clientOAuthSessionItem.setClientId(clientId);
        clientOAuthSessionItem.setRedirectUri(claimsSet.getStringClaim("redirect_uri"));
        clientOAuthSessionItem.setState(claimsSet.getStringClaim("state"));
        clientOAuthSessionItem.setUserId(claimsSet.getSubject());
        clientOAuthSessionItem.setScope(claimsSet.getStringClaim("scope"));
        clientOAuthSessionItem.setGovukSigninJourneyId(
                claimsSet.getStringClaim("govuk_signin_journey_id"));

        // This is a temporary fix to handle the case where the vtr claim is not present in the JWT
        // Reverification featureSet scenario.
        List<String> vtr = claimsSet.getStringListClaim("vtr");
        if (vtr == null || vtr.isEmpty()) {
            vtr = List.of("P2");
        }

        clientOAuthSessionItem.setVtr(vtr);
        clientOAuthSessionItem.setScope(claimsSet.getStringClaim("scope"));
        clientOAuthSessionItem.setReproveIdentity(claimsSet.getBooleanClaim("reprove_identity"));
        clientOAuthSessionItem.setEvcsAccessToken(evcsAccessToken);
        dataStore.create(clientOAuthSessionItem, BACKEND_SESSION_TTL);

        return clientOAuthSessionItem;
    }

    public ClientOAuthSessionItem generateErrorClientSessionDetails(
            String clientOAuthSessionId,
            String redirectUri,
            String clientId,
            String state,
            String govukSigninJourneyId) {
        ClientOAuthSessionItem clientOAuthSessionErrorItem = new ClientOAuthSessionItem();
        clientOAuthSessionErrorItem.setClientOAuthSessionId(clientOAuthSessionId);
        clientOAuthSessionErrorItem.setResponseType(null);
        clientOAuthSessionErrorItem.setClientId(clientId);
        clientOAuthSessionErrorItem.setRedirectUri(redirectUri);
        clientOAuthSessionErrorItem.setState(state);
        clientOAuthSessionErrorItem.setUserId(null);
        clientOAuthSessionErrorItem.setGovukSigninJourneyId(govukSigninJourneyId);
        clientOAuthSessionErrorItem.setReproveIdentity(null);

        dataStore.create(clientOAuthSessionErrorItem, BACKEND_SESSION_TTL);

        return clientOAuthSessionErrorItem;
    }
}
