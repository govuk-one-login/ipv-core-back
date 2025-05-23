package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;

import java.text.ParseException;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CLIENT_OAUTH_SESSIONS_TABLE_NAME;

public class ClientOAuthSessionDetailsService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final DataStore<ClientOAuthSessionItem> dataStore;
    private final ConfigService configService;

    public ClientOAuthSessionDetailsService(
            DataStore<ClientOAuthSessionItem> dataStore, ConfigService configService) {
        this.dataStore = dataStore;
        this.configService = configService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ClientOAuthSessionDetailsService(ConfigService configService) {
        this(
                DataStore.create(
                        CLIENT_OAUTH_SESSIONS_TABLE_NAME,
                        ClientOAuthSessionItem.class,
                        configService),
                configService);
    }

    public ClientOAuthSessionItem getClientOAuthSession(String clientOAuthSessionId)
            throws ClientOauthSessionNotFoundException {
        var clientOauthSession = dataStore.getItem(clientOAuthSessionId);
        if (clientOauthSession == null) {
            throw new ClientOauthSessionNotFoundException();
        }
        return clientOauthSession;
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
        clientOAuthSessionItem.setGovukSigninJourneyId(
                claimsSet.getStringClaim("govuk_signin_journey_id"));
        clientOAuthSessionItem.setVtr(getEnabledVtr(claimsSet.getStringListClaim("vtr")));
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
        clientOAuthSessionErrorItem.setErrorClientSession(true);

        dataStore.create(clientOAuthSessionErrorItem, BACKEND_SESSION_TTL);

        return clientOAuthSessionErrorItem;
    }

    public void updateClientSessionDetails(ClientOAuthSessionItem clientOAuthSessionItem) {
        dataStore.update(clientOAuthSessionItem);
    }

    private List<String> getEnabledVtr(List<String> vtr) {
        if (!configService.enabled(CoreFeatureFlag.P1_JOURNEYS_ENABLED)
                && vtr.contains(Vot.P1.name())) {
            LOGGER.warn(
                    LogHelper.buildLogMessage("Received P1 VTR, but P1 journeys are not enabled"));
            return vtr.stream().filter(vot -> !Vot.P1.name().equals(vot)).toList();
        }
        return vtr;
    }
}
