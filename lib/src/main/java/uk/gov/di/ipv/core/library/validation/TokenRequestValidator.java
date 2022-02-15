package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;

import java.text.ParseException;
import java.util.Map;

public class TokenRequestValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenRequestValidator.class);

    public ValidationResult<ErrorObject> validateExtractedJwt(String requestBody) {

        Map<String, String> stringMap = RequestHelper.parseRequestBody(requestBody);

        try {
            SignedJWT clientJwt =
                    SignedJWT.parse(String.valueOf(stringMap.get("client_assertion")));

            JWTClaimsSet claimsSet = clientJwt.getJWTClaimsSet();

            if (claimsSet != null) {
                return ValidationResult.createValidResult();
            }
        } catch (ParseException e) {
            LOGGER.error("Unable to parse Claims set {} ", e.getMessage());
            return new ValidationResult<>(false, OAuth2Error.INVALID_CLIENT);
        }
        return ValidationResult.createValidResult();
    }
}
