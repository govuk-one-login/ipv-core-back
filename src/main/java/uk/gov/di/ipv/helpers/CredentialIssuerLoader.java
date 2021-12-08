package uk.gov.di.ipv.helpers;

import com.amazonaws.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLParser;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.CredentialIssuers;

import java.io.IOException;

public class CredentialIssuerLoader {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialIssuerLoader.class);

    private CredentialIssuerLoader() {}

    public static CredentialIssuers loadCredentialIssuers(String credentialIssuerConfigBase64) {
        YAMLFactory yamlFactory = new YAMLFactory();
        ObjectMapper mapper = new ObjectMapper(yamlFactory);
        CredentialIssuers credentialIssuers;
        try {
            byte[] decode = Base64.decode(credentialIssuerConfigBase64);
            YAMLParser yamlParser = yamlFactory.createParser(decode);
            credentialIssuers = mapper.readValue(yamlParser, CredentialIssuers.class);
            credentialIssuers.setSource(credentialIssuerConfigBase64);
            LOGGER.info("Loaded Credential Issuers: {}", credentialIssuers);
        } catch (IllegalArgumentException | IOException e) {
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_DECODE_CREDENTIAL_ISSUER_CONFIG);
        }

        return credentialIssuers;
    }
}
