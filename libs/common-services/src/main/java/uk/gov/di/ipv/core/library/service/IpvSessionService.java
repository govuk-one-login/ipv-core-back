package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.retry.Retry;
import uk.gov.di.ipv.core.library.retry.Sleeper;

import java.time.Instant;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.IPV_SESSIONS_TABLE_NAME;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.REVERIFICATION;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.TECHNICAL_ERROR;

public class IpvSessionService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String START_STATE = "START";
    private static final String ERROR_STATE = "ERROR";

    private final DataStore<IpvSessionItem> dataStore;
    private final Sleeper sleeper;

    public IpvSessionService(DataStore<IpvSessionItem> dataStore, Sleeper sleeper) {
        this.dataStore = dataStore;
        this.sleeper = sleeper;
    }

    @ExcludeFromGeneratedCoverageReport
    public IpvSessionService(ConfigService configService) {
        dataStore =
                new DataStore<>(
                        configService.getEnvironmentVariable(IPV_SESSIONS_TABLE_NAME),
                        IpvSessionItem.class,
                        DataStore.getClient(),
                        configService);
        this.sleeper = new Sleeper();
    }

    public IpvSessionItem getIpvSession(String ipvSessionId) {
        return dataStore.getItem(ipvSessionId);
    }

    public Optional<IpvSessionItem> getIpvSessionByAuthorizationCode(String authorizationCode) {
        IpvSessionItem ipvSessionItem =
                dataStore.getItemByIndex(
                        "authorizationCode", DigestUtils.sha256Hex(authorizationCode));
        return Optional.ofNullable(ipvSessionItem);
    }

    public Optional<IpvSessionItem> getIpvSessionByAccessToken(String accessToken) {
        try {
            var ipvSessionItem =
                    Retry.runTaskWithBackoff(
                            sleeper,
                            7,
                            10,
                            (isLastAttempt) -> {
                                var item =
                                        dataStore.getItemByIndex(
                                                "accessToken", DigestUtils.sha256Hex(accessToken));
                                if (item == null) {
                                    throw new RetryableException();
                                }
                                return Optional.of(item);
                            });
            return Optional.ofNullable(ipvSessionItem);
        } catch (InterruptedException e) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "getIpvSessionByAccessToken() backoff and retry sleep was interrupted"));
            Thread.currentThread().interrupt();
        } catch (NonRetryableException e) {
            LOGGER.warn(
                    LogHelper.buildErrorMessage(
                            "getIpvSessionByAccessToken() exception occurred retrying getItemByIndex",
                            e));
        }
        return Optional.empty();
    }

    public IpvSessionItem generateIpvSession(
            String clientOAuthSessionId,
            ErrorObject errorObject,
            String emailAddress,
            boolean isReverification) {

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setClientOAuthSessionId(clientOAuthSessionId);
        LogHelper.attachIpvSessionIdToLogs(ipvSessionItem.getIpvSessionId());

        ipvSessionItem.setCreationDateTime(Instant.now().toString());

        ipvSessionItem.setVot(Vot.P0);

        if (errorObject == null) {
            if (isReverification) {
                ipvSessionItem.pushState(new JourneyState(REVERIFICATION, START_STATE));
            } else {
                ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE));
            }
        } else {
            ipvSessionItem.pushState(new JourneyState(TECHNICAL_ERROR, ERROR_STATE));
            ipvSessionItem.setErrorCode(errorObject.getCode());
            ipvSessionItem.setErrorDescription(errorObject.getDescription());
        }

        if (emailAddress != null) {
            ipvSessionItem.setEmailAddress(emailAddress);
        }

        dataStore.create(ipvSessionItem, BACKEND_SESSION_TTL);

        return ipvSessionItem;
    }

    public void setAuthorizationCode(
            IpvSessionItem ipvSessionItem, String authorizationCode, String redirectUrl) {
        AuthorizationCodeMetadata authorizationCodeMetadata = new AuthorizationCodeMetadata();
        authorizationCodeMetadata.setCreationDateTime(Instant.now().toString());
        authorizationCodeMetadata.setRedirectUrl(redirectUrl);
        ipvSessionItem.setAuthorizationCode(DigestUtils.sha256Hex(authorizationCode));
        ipvSessionItem.setAuthorizationCodeMetadata(authorizationCodeMetadata);
        updateIpvSession(ipvSessionItem);
    }

    public void setAccessToken(IpvSessionItem ipvSessionItem, BearerAccessToken accessToken) {
        AccessTokenMetadata accessTokenMetadata = new AccessTokenMetadata();
        accessTokenMetadata.setCreationDateTime(Instant.now().toString());
        accessTokenMetadata.setExpiryDateTime(toExpiryDateTime(accessToken.getLifetime()));
        ipvSessionItem.setAccessToken(DigestUtils.sha256Hex(accessToken.getValue()));
        ipvSessionItem.setAccessTokenMetadata(accessTokenMetadata);
        updateIpvSession(ipvSessionItem);
    }

    public void revokeAccessToken(IpvSessionItem ipvSessionItem) throws IllegalArgumentException {
        AccessTokenMetadata accessTokenMetadata = ipvSessionItem.getAccessTokenMetadata();
        if (StringUtils.isBlank(accessTokenMetadata.getRevokedAtDateTime())) {
            accessTokenMetadata.setRevokedAtDateTime(Instant.now().toString());
            ipvSessionItem.setAccessTokenMetadata(accessTokenMetadata);
            updateIpvSession(ipvSessionItem);
        }
    }

    public void updateIpvSession(IpvSessionItem updatedIpvSessionItem) {
        dataStore.update(updatedIpvSessionItem);
    }

    private String toExpiryDateTime(long expirySeconds) {
        return Instant.now().plusSeconds(expirySeconds).toString();
    }
}
