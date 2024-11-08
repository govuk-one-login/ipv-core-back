package uk.gov.di.ipv.core.library.oauthkeyservice;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.oauthkeyservice.domain.CachedOAuthCriEncryptionKey;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_OK;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class OAuthKeyService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConcurrentHashMap<String, CachedOAuthCriEncryptionKey> cachedOAuthEncryptionKeys =
            new ConcurrentHashMap<>();

    private final HttpClient httpClient;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public OAuthKeyService(ConfigService configService) {
        this.configService = configService;
        this.httpClient = HttpClient.newHttpClient();
    }

    @ExcludeFromGeneratedCoverageReport
    public OAuthKeyService(ConfigService configService, HttpClient httpClient) {
        this.configService = configService;
        this.httpClient = httpClient;
    }

    public RSAKey getEncryptionKey(OauthCriConfig criConfig) throws ParseException {
        var jwksUrl = criConfig.getJwksUrl();
        var keyFromConfig = criConfig.getParsedEncryptionKey();

        if (jwksUrl != null) {
            if (cachedOAuthEncryptionKeys.containsKey(jwksUrl.toString())
                    && !cachedOAuthEncryptionKeys.get(jwksUrl.toString()).isExpired()) {
                return cachedOAuthEncryptionKeys.get(jwksUrl.toString()).key();
            }

            var keys = getKeysFromJwksEndpoint(jwksUrl);

            var firstEncKey =
                    keys.stream().filter(key -> key.getKeyUse() == KeyUse.ENCRYPTION).findFirst();
            if (firstEncKey.isPresent()) {
                var cacheDuration =
                        configService.getParameter(
                                ConfigurationVariable.OAUTH_KEY_CACHE_DURATION_MINS);
                var parsedKey = firstEncKey.get().toRSAKey();

                cacheEncryptionKey(parsedKey, jwksUrl.toString(), Integer.parseInt(cacheDuration));
                return parsedKey;
            }
        }

        return keyFromConfig;
    }

    private void cacheEncryptionKey(RSAKey key, String jwksUrl, Integer cacheDuration) {
        // Cache the key in a variable outside of the handler so it exists in
        // the Lambda's memory and is still accessible between invocations that
        // occur at short intervals from one another
        var expiryDate = LocalDateTime.now().plusMinutes(cacheDuration);
        cachedOAuthEncryptionKeys.put(jwksUrl, new CachedOAuthCriEncryptionKey(key, expiryDate));
    }

    @Tracing
    private List<JWK> getKeysFromJwksEndpoint(URI jwksEndpoint) {
        try {
            LOGGER.info(LogHelper.buildLogMessage("Retrieving key from well-known endpoint."));
            var request = HttpRequest.newBuilder().uri(jwksEndpoint).GET().build();
            var httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (httpResponse.statusCode() != SC_OK) {
                LOGGER.error(
                        LogHelper.buildLogMessage("Error retrieving JWKS")
                                .with(LOG_STATUS_CODE.getFieldName(), httpResponse.statusCode()));
                return List.of();
            }

            return JWKSet.parse(httpResponse.body()).getKeys();
        } catch (IOException | java.text.ParseException e) {
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            String.format("Error retrieving public encryption key: %s", e)));
            return List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            "Interrupted while trying to fetch public key for encryption."));
            return List.of();
        }
    }
}
