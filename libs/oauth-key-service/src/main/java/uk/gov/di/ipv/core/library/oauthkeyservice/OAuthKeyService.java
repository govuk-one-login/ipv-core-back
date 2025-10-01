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
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParseException;
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

    public RSAKey getEncryptionKey(OauthCriConfig criConfig) {
        var jwksUrl = criConfig.getJwksUrl();
        if (jwksUrl == null) {
            throw new ConfigParameterNotFoundException("JWKS URL is not set in CRI config");
        }
        return getCachedJWKSet(jwksUrl).filter(ENC_USE_MATCHER).getKeys().stream()
                .findFirst()
                .map(JWK::toRSAKey)
                .orElseThrow();
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
                            .getPublicKeyMaterialForCoreToVerify());
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
                            .getPublicKeyMaterialForCoreToVerify());
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
                            .getPublicKeyMaterialForCoreToVerify());
        }

        LOGGER.info(
                LogHelper.buildLogMessage("Found signing key by key ID")
                        .with(LOG_KEY_ID.getFieldName(), keyId)
                        .with(LOG_CLIENT_ID.getFieldName(), clientId));
        return keyByKeyId.toECKey();
    }

    private URI getClientJwksUrl(String clientId) {
        try {
            var jwksUrl = configService.getConfiguration().getClientConfig(clientId).getJwksUrl();
            if (jwksUrl == null) {
                return null;
            }
            return URI.create(jwksUrl);
        } catch (ConfigParameterNotFoundException e) {
            return null;
        }
    }

    private JWKSet getCachedJWKSet(URI jwksUrl) {
        var cachedJWKSet =
                cachedJwkSets.compute(
                        jwksUrl,
                        (key, existingCachedJWKSet) -> {
                            if (existingCachedJWKSet == null || existingCachedJWKSet.isExpired()) {
                                try {
                                    return createCachedJWKSet(jwksUrl);
                                } catch (Exception e) {
                                    LOGGER.error(
                                            LogHelper.buildErrorMessage(
                                                            "Error creating cached JWK set", e)
                                                    .with(LOG_JWKS_URL.getFieldName(), jwksUrl));
                                }
                            }
                            return existingCachedJWKSet;
                        });
        if (cachedJWKSet == null) {
            throw new ConfigParseException(
                    "Cached JWK set cannot be retrieved, nor does it have a cached value.");
        }
        return cachedJWKSet.jwkSet();
    }

    private CachedJWKSet createCachedJWKSet(URI jwksEndpoint)
            throws IOException, ParseException, ConfigException {
        return new CachedJWKSet(
                getJWKSetFromJwksEndpoint(jwksEndpoint),
                Instant.now().plus(configService.getOauthKeyCacheDurationMins(), MINUTES));
    }

    private JWKSet getJWKSetFromJwksEndpoint(URI jwksEndpoint)
            throws IOException, ParseException, ConfigException {
        try {
            LOGGER.info(LogHelper.buildLogMessage("Retrieving JWKSet from well-known endpoint"));
            var request = HttpRequest.newBuilder().uri(jwksEndpoint).GET().build();
            var httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (httpResponse.statusCode() != SC_OK) {
                LOGGER.error(
                        LogHelper.buildLogMessage("Error retrieving JWKS")
                                .with(LOG_STATUS_CODE.getFieldName(), httpResponse.statusCode())
                                .with(LOG_JWKS_URL.getFieldName(), jwksEndpoint));
                throw new ConfigException("Error retrieving JWKs");
            }

            return JWKSet.parse(httpResponse.body());
        } catch (IOException | java.text.ParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Error parsing JWKSet key", e)
                            .with(LOG_JWKS_URL.getFieldName(), jwksEndpoint));
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.error(
                    LogHelper.buildErrorMessage("Interrupted while trying to fetch JWKSet.", e)
                            .with(LOG_JWKS_URL.getFieldName(), jwksEndpoint));
            throw new ConfigException("Interrupted while trying to fetch JWKSet");
        }
    }
}
