package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class TokenRequestValidatorTest {

    private TokenRequestValidator validator;

    @BeforeEach
    void setUp() {
        validator = new TokenRequestValidator();
    }

    @Test
    void shouldSuccessFullyReadClaimSetProvided() {
        String tokenRequestBody =
                "code=12345&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        ValidationResult<ErrorObject> extractJwt = validator.validateExtractedJwt(tokenRequestBody);
        assertEquals(true, extractJwt.isValid());
    }

    @Test
    void shouldReadClaimSetProvidedAndError() {
        String tokenRequestBody =
                "code=12345&client_assertion=&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        ValidationResult<ErrorObject> extractJwt = validator.validateExtractedJwt(tokenRequestBody);
        assertEquals(true, !extractJwt.isValid());
        assertEquals(OAuth2Error.INVALID_CLIENT_CODE, extractJwt.getError().getCode());
    }

    @Test
    void shouldReadClaimSetProvidedAndErrorWithMissingClaimSet() {
        String tokenRequestBody =
                "code=12345&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        ValidationResult<ErrorObject> extractJwt = validator.validateExtractedJwt(tokenRequestBody);
        assertEquals(true, !extractJwt.isValid());
        assertEquals(OAuth2Error.INVALID_CLIENT_CODE, extractJwt.getError().getCode());
    }
}
