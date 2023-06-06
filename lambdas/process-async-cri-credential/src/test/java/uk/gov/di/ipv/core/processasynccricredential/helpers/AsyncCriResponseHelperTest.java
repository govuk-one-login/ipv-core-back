package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.processasynccricredential.domain.ErrorAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.DEFAULT_CREDENTIAL_ISSUER;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.getAsyncResponseMessage;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.isSuccessAsyncCriResponse;

@ExtendWith(MockitoExtension.class)
class AsyncCriResponseHelperTest {

    private static final String TEST_USER = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private static final String TEST_OAUTH_STATE = "abcdabcdabcdabcd";

    private static final String TEST_JWT = "jwt.as.string";

    private static final String TEST_ERROR = "an error";
    private static final String TEST_ERROR_DESCRIPTION = "a description of the error";
    private static final String TEST_SUCCESS_ASYNC_RESPONSE_MESSAGE =
            String.format(
                    "{\"sub\":\"%s\",\"state\":\"%s\",\"https://vocab.account.gov.uk/v1/credentialJWT\":[\"%s\"]}",
                    TEST_USER, TEST_OAUTH_STATE, TEST_JWT);

    private static final String TEST_ERROR_ASYNC_RESPONSE_MESSAGE =
            String.format(
                    "{\"sub\":\"%s\",\"state\":\"%s\",\"error\":\"%s\",\"error_description\":\"%s\"}",
                    TEST_USER, TEST_OAUTH_STATE, TEST_ERROR, TEST_ERROR_DESCRIPTION);

    @Test
    void shouldCreateSuccessResponseForSuccessResponseMessage() throws JsonProcessingException {
        var response = getAsyncResponseMessage(TEST_SUCCESS_ASYNC_RESPONSE_MESSAGE);
        assertTrue(isSuccessAsyncCriResponse(response));
        var successAsyncCriResponse = (SuccessAsyncCriResponse) response;
        assertEquals(TEST_USER, successAsyncCriResponse.getUserId());
        assertEquals(DEFAULT_CREDENTIAL_ISSUER, successAsyncCriResponse.getCredentialIssuer());
        assertEquals(1, successAsyncCriResponse.getVerifiableCredentialJWTs().size());
        assertEquals(TEST_JWT, successAsyncCriResponse.getVerifiableCredentialJWTs().get(0));
    }

    @Test
    void shouldCreateErrorResponseForErrorResponseMessage() throws JsonProcessingException {
        var response = getAsyncResponseMessage(TEST_ERROR_ASYNC_RESPONSE_MESSAGE);
        assertFalse(isSuccessAsyncCriResponse(response));
        var errorAsyncCriResponse = (ErrorAsyncCriResponse) response;
        assertEquals(TEST_USER, errorAsyncCriResponse.getUserId());
        assertEquals(DEFAULT_CREDENTIAL_ISSUER, errorAsyncCriResponse.getCredentialIssuer());
        assertEquals(TEST_ERROR, errorAsyncCriResponse.getError());
        assertEquals(TEST_ERROR_DESCRIPTION, errorAsyncCriResponse.getErrorDescription());
    }
}
