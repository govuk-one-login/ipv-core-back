package uk.gov.di.ipv.core.library.oauthkeyservice;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_OK;

public class OAuthKeyService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final HttpClient httpClient;

    @ExcludeFromGeneratedCoverageReport
    public OAuthKeyService() {
        this.httpClient = HttpClient.newHttpClient();
    }

    @ExcludeFromGeneratedCoverageReport
    public OAuthKeyService(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public RSAKey getValidEncryptionKey(OauthCriConfig criConfig) throws ParseException {
        var jwksUrl = criConfig.getJwksUrl();
        var keyFromConfig = criConfig.getParsedEncryptionKey();

        if (jwksUrl != null) {
            var keys = getKeysFromJwksEndpoint(jwksUrl);

            var firstEncKey =
                    keys.stream().filter(key -> key.getKeyUse() == KeyUse.ENCRYPTION).findFirst();
            if (firstEncKey.isPresent()) {
                return firstEncKey.get().toRSAKey();
            }
        }

        return keyFromConfig;
    }

    @Tracing
    private List<JWK> getKeysFromJwksEndpoint(URI jwksEndpoint) {
        try {
            LOGGER.info(LogHelper.buildLogMessage("Retrieving key from well-known endpoint."));
            var request = HttpRequest.newBuilder().uri(jwksEndpoint).GET().build();
            var httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (httpResponse.statusCode() != SC_OK) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                String.format(
                                        "%d: Error retrieving public encryption key.",
                                        httpResponse.statusCode())));
                return List.of();
            }

            return JWKSet.parse(httpResponse.body()).getKeys();
        } catch (IOException | java.text.ParseException e) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            String.format("Error retrieving public encryption key: %s", e)));
            return List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "Interrupted while trying to fetch public key for encryption."));
            return List.of();
        }
    }
}
