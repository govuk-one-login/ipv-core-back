package uk.gov.di.ipv.core.library.oauthkeyservice;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.oauthkeyservice.domain.CachedJWKSet;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.tracing.TracingHttpClient;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

import static com.nimbusds.jose.jwk.KeyUse.ENCRYPTION;
import static com.nimbusds.jose.jwk.KeyUse.SIGNATURE;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_OK;
import static java.time.temporal.ChronoUnit.MINUTES;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CLIENT_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ISSUER;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JWKS_URL;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_KEY_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class OAuthKeyService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JWKMatcher SIG_USE_MATCHER =
            new JWKMatcher.Builder().keyUse(SIGNATURE).build();
    private static final JWKMatcher ENC_USE_MATCHER =
            new JWKMatcher.Builder().keyUse(ENCRYPTION).build();

    private final ConcurrentHashMap<URI, CachedJWKSet> cachedJwkSets = new ConcurrentHashMap<>();
    private final HttpClient httpClient;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public OAuthKeyService(ConfigService configService) {
        this.configService = configService;
        this.httpClient = TracingHttpClient.newHttpClient();
    }

    @ExcludeFromGeneratedCoverageReport
    public OAuthKeyService(ConfigService configService, HttpClient httpClient) {
        this.configService = configService;
        this.httpClient = httpClient;
    }

    public RSAKey getEncryptionKey(OauthCriConfig criConfig) throws ParseException {
        var jwksUrl = criConfig.getJwksUrl();
        var keyFromConfig = criConfig.getParsedEncryptionKey();

        return jwksUrl == null
                ? keyFromConfig
                : getCachedJWKSet(jwksUrl).filter(ENC_USE_MATCHER).getKeys().stream()
                        .findFirst()
                        .map(JWK::toRSAKey)
                        .orElseGet(
                                () -> {
                                    LOGGER.warn(
                                            LogHelper.buildLogMessage(
                                                            "No encryption key found, returning key from config")
                                                    .with(
                                                            LOG_CRI_ISSUER.getFieldName(),
                                                            criConfig.getComponentId())
                                                    .with(LOG_JWKS_URL.getFieldName(), jwksUrl));
                                    return keyFromConfig;
                                });
    }

    public ECKey getClientSigningKey(String clientId, JWSHeader jwsHeader) throws ParseException {
        var keyId = jwsHeader.getKeyID();
        if (keyId == null) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                                    "No key ID found in header, returning key from config")
                            .with(LOG_CLIENT_ID.getFieldName(), clientId));
            return ECKey.parse(
                    configService
                            .getConfiguration()
                            .getClientConfig(clientId)
                            .getPublicKeyMaterialForCoreToVerify()
                            .toString());
        }

        var jwksUrl = getClientJwksUrl(clientId);
        if (jwksUrl == null) {
            LOGGER.warn(
                    LogHelper.buildLogMessage("JWKS URL not configured, returning key from config")
                            .with(LOG_CLIENT_ID.getFieldName(), clientId));
            return ECKey.parse(
                    configService
                            .getConfiguration()
                            .getClientConfig(clientId)
                            .getPublicKeyMaterialForCoreToVerify()
                            .toString());
        }

        var keyByKeyId = getCachedJWKSet(jwksUrl).filter(SIG_USE_MATCHER).getKeyByKeyId(keyId);
        if (keyByKeyId == null) {
            LOGGER.warn(
                    LogHelper.buildLogMessage("Key not found by key ID, returning key from config")
                            .with(LOG_KEY_ID.getFieldName(), keyId)
                            .with(LOG_CLIENT_ID.getFieldName(), clientId)
                            .with(LOG_JWKS_URL.getFieldName(), jwksUrl));
            return ECKey.parse(
                    configService
                            .getConfiguration()
                            .getClientConfig(clientId)
                            .getPublicKeyMaterialForCoreToVerify()
                            .toString());
        }

        LOGGER.info(
                LogHelper.buildLogMessage("Found signing key by key ID")
                        .with(LOG_KEY_ID.getFieldName(), keyId)
                        .with(LOG_CLIENT_ID.getFieldName(), clientId));
        return keyByKeyId.toECKey();
    }

    private URI getClientJwksUrl(String clientId) {
        try {
            return URI.create(
                    configService
                            .getConfiguration()
                            .getClientConfig(clientId)
                            .getJwksUrl()
                            .toString());
        } catch (ConfigParameterNotFoundException e) {
            return null;
        }
    }

    private JWKSet getCachedJWKSet(URI jwksUrl) {
        return cachedJwkSets
                .compute(
                        jwksUrl,
                        (key, existingCachedJWKSet) -> {
                            if (existingCachedJWKSet == null || existingCachedJWKSet.isExpired()) {
                                return createCachedJWKSet(jwksUrl);
                            }
                            return existingCachedJWKSet;
                        })
                .jwkSet();
    }

    private CachedJWKSet createCachedJWKSet(URI jwksEndpoint) {
        return new CachedJWKSet(
                getJWKSetFromJwksEndpoint(jwksEndpoint),
                Instant.now()
                        .plus(
                                configService.getLongParameter(
                                        ConfigurationVariable.OAUTH_KEY_CACHE_DURATION_MINS),
                                MINUTES));
    }

    private JWKSet getJWKSetFromJwksEndpoint(URI jwksEndpoint) {
        try {
            LOGGER.info(LogHelper.buildLogMessage("Retrieving JWKSet from well-known endpoint"));
            var request = HttpRequest.newBuilder().uri(jwksEndpoint).GET().build();
            var httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (httpResponse.statusCode() != SC_OK) {
                LOGGER.error(
                        LogHelper.buildLogMessage("Error retrieving JWKS")
                                .with(LOG_STATUS_CODE.getFieldName(), httpResponse.statusCode())
                                .with(LOG_JWKS_URL.getFieldName(), jwksEndpoint));
                return new JWKSet();
            }

            return JWKSet.parse(httpResponse.body());
        } catch (IOException | java.text.ParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Error parsing JWKSet key", e)
                            .with(LOG_JWKS_URL.getFieldName(), jwksEndpoint));
            return new JWKSet();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.error(
                    LogHelper.buildErrorMessage("Interrupted while trying to fetch JWKSet.", e)
                            .with(LOG_JWKS_URL.getFieldName(), jwksEndpoint));
            return new JWKSet();
        }
    }
}
