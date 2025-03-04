package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.domain.CriJourneyRequest;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnknownCoiCheckTypeException;
import uk.gov.di.ipv.core.library.exceptions.UnknownProcessIdentityTypeException;
import uk.gov.di.ipv.core.library.exceptions.UnknownResetTypeException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_BAD_REQUEST;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.Cri.CLAIMED_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_RESET_TYPE;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.STANDARD;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.NAME_ONLY_CHANGE;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.ENCODED_DEVICE_INFORMATION_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.FEATURE_SET_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IP_ADDRESS_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getClientOAuthSessionIdAllowMissing;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getEncodedDeviceInformation;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getFeatureSet;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getHeaderByKey;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionIdAllowMissing;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getLanguage;

class RequestHelperTest {
    private final String TEST_IPV_SESSION_ID = "a-session-id";
    private final String TEST_IP_ADDRESS = "127.0.0.1";
    private final String TEST_FEATURE_SET = "test-feature-set";
    private final String TEST_CLIENT_SESSION_ID = "client-session-id";
    private final String TEST_JOURNEY = "/journey/next";
    private static final String CONTEXT = "context";
    private static final String BANK_ACCOUNT_CONTEXT = "bankAccountContext";
    private static final String TEST_JOURNEY_WITH_CONTEXT =
            String.format("claimedIdentity?%s=%s", CONTEXT, BANK_ACCOUNT_CONTEXT);
    private static final String SCOPE = "scope";
    private static final String IDENTITY_CHECK_SCOPE = "identityCheck";
    private static final String TEST_JOURNEY_WITH_SCOPE =
            String.format("claimedIdentity?%s=%s", SCOPE, IDENTITY_CHECK_SCOPE);
    private static final String TEST_JOURNEY_WITH_CONTEXT_AND_SCOPE =
            String.format(
                    "claimedIdentity?%s=%s&%s=%s",
                    CONTEXT, BANK_ACCOUNT_CONTEXT, SCOPE, IDENTITY_CHECK_SCOPE);
    private static final String TEST_JOURNEY_WITH_EMPTY_CONTEXT =
            String.format("claimedIdentity?%s=", CONTEXT);

    @Test
    void getHeaderByKeyShouldReturnNullIfHeaderNotFound() {
        assertNull(getHeaderByKey(Map.of("tome", "toyou"), "ohdearohdear"));
    }

    @Test
    void getHeaderByKeyShouldReturnNullIfHeaderPassedNull() {
        assertNull(getHeaderByKey(null, "ohdearohdear"));
    }

    @Test
    void getIpvSessionIdShouldReturnSessionId() throws HttpResponseExceptionWithErrorBody {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, "a-session-id"));

        assertEquals("a-session-id", getIpvSessionId(event));
    }

    @Test
    void getIpvSessionIdShouldReturnSessionIdFromJourneyEvent()
            throws HttpResponseExceptionWithErrorBody {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .build();

        assertEquals("a-session-id", getIpvSessionId(event));
    }

    @Test
    void getIpvSessionIdShouldThrowIfSessionIdIsNullInJourneyEvent() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(null)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .build();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class, () -> getIpvSessionId(event));

        assertEquals(SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getIpvSessionIdShouldThrowIfSessionIdIsEmptyStringInJourneyEvent() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId("")
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .build();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class, () -> getIpvSessionId(event));

        assertEquals(SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getIpvSessionIdShouldThrowIfSessionIdIsNullInEvent() {
        var event = new APIGatewayProxyRequestEvent();
        HashMap<String, String> headers = new HashMap<>();
        headers.put(IPV_SESSION_ID_HEADER, null);

        event.setHeaders(headers);

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class, () -> getIpvSessionId(event));

        assertEquals(SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getIpvSessionIdShouldThrowIfSessionIdIsEmptyStringInEvent() {
        var event = new APIGatewayProxyRequestEvent();

        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, ""));

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class, () -> getIpvSessionId(event));

        assertEquals(SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getEncodedDeviceInformationShouldReturnDeviceInformation() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(ENCODED_DEVICE_INFORMATION_HEADER, "test-device-information"));

        assertEquals("test-device-information", getEncodedDeviceInformation(event));
    }

    @Test
    void getIpAddressShouldReturnIpAddress() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(IP_ADDRESS_HEADER, "a-client-source-ip"));

        assertEquals("a-client-source-ip", getIpAddress(event));
    }

    @Test
    void getIpAddressIdShouldReturnNullIfIpAddressIsEmptyString() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(IP_ADDRESS_HEADER, ""));

        var result = getIpAddress(event);

        assertNull(result);
    }

    @Test
    void getClientOAuthSessionIdShouldReturnClientSessionId() {
        var event = new JourneyRequest();
        String clientSessionIdInHeader = "client-session-id";
        event.setClientOAuthSessionId(clientSessionIdInHeader);

        assertEquals(clientSessionIdInHeader, getClientOAuthSessionIdAllowMissing(event));
    }

    @Test
    void getClientOAuthSessionIdShouldReturnNullIfClientSessionIdIsNull() {
        var event = new JourneyRequest();
        event.setClientOAuthSessionId(null);

        assertNull(getClientOAuthSessionIdAllowMissing(event));
    }

    @Test
    void getLanguageInCriRequestShouldReturnLanguage() {
        // Arrange
        var event = new CriJourneyRequest();
        String language = "some-language";
        event.setLanguage(language);

        // Act & Assert
        assertEquals(language, getLanguage(event));
    }

    @Test
    void getLanguageInCriRequestShouldReturnNullIfLanguageIsEmpty() {
        // Arrange
        var event = new CriJourneyRequest();
        event.setLanguage("");

        // Act
        var result = getLanguage(event);

        // Assert
        assertNull(result);
    }

    @Test
    void forJourneyRequestShouldReturnClientSessionId() throws HttpResponseExceptionWithErrorBody {
        String clientSessionId = "client-session-id";
        String ipvSessionId = "a-session-id";
        String ipAddress = "a-ipaddress";
        String featureSet = "a-feature-set";
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(ipvSessionId)
                        .ipAddress(ipAddress)
                        .clientOAuthSessionId(clientSessionId)
                        .journey(DCMAW.getId())
                        .featureSet(featureSet)
                        .build();

        assertEquals(clientSessionId, getClientOAuthSessionIdAllowMissing(event));
        assertEquals(ipvSessionId, getIpvSessionId(event));
        assertEquals(ipAddress, getIpAddress(event));
        assertEquals(List.of(featureSet), getFeatureSet(event));
    }

    @Test
    void forJourneyRequestShouldReturnNullIfSessionIdIsNull()
            throws HttpResponseExceptionWithErrorBody {
        String clientSessionId = "client-session-id";
        String ipAddress = "a-ipaddress";
        String featureSet = "a-feature-set";
        var event =
                JourneyRequest.builder()
                        .ipAddress(ipAddress)
                        .clientOAuthSessionId(clientSessionId)
                        .journey(DCMAW.getId())
                        .featureSet(featureSet)
                        .build();

        assertNull(getIpvSessionIdAllowMissing(event));
    }

    @Test
    void getFeatureSetShouldReturnFeatureSetId() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(FEATURE_SET_HEADER, TEST_FEATURE_SET));

        assertEquals(Arrays.asList(TEST_FEATURE_SET), getFeatureSet(event));
    }

    @Test
    void getFeatureSetShouldReturnFeatureSetForHeaderMap() {
        Map<String, String> headerMap = new HashMap<>();
        headerMap.put(FEATURE_SET_HEADER, TEST_FEATURE_SET);

        assertEquals(Arrays.asList(TEST_FEATURE_SET), getFeatureSet(headerMap));
    }

    @Test
    void getFeatureSetShouldReturnFeatureSetIdFromJourney() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .build();
        assertEquals(List.of(TEST_FEATURE_SET), getFeatureSet(event));
    }

    @Test
    void getFeatureSetShouldReturnEmptyListFromJourneyIfNoFeatureSet() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .build();
        assertTrue(getFeatureSet(event).isEmpty());
    }

    @Test
    void getJourneyEventShouldReturnJourneyEvent() throws Exception {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .build();

        assertEquals("next", RequestHelper.getJourneyEvent(event));
    }

    @Test
    void getJourneyEventShouldThrowIfJourneyMissing() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .build();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getJourneyEvent(event));
        assertEquals(ErrorResponse.MISSING_JOURNEY_EVENT, exception.getErrorResponse());
        assertEquals(SC_BAD_REQUEST, exception.getResponseCode());
    }

    @ParameterizedTest
    @MethodSource("journeyUriParameters")
    void getJourneyShouldReturnJourneyWithParametersFromJourneyRequest(
            String journey, String expectedContext, String expectedScope) throws Exception {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(journey)
                        .build();

        assertEquals(CLAIMED_IDENTITY.getId(), event.getJourneyUri().getPath());
        assertEquals(expectedContext, RequestHelper.getJourneyParameter(event, CONTEXT));
        assertEquals(expectedScope, RequestHelper.getJourneyParameter(event, SCOPE));
    }

    static Stream<Arguments> journeyUriParameters() {
        return Stream.of(
                Arguments.of(TEST_JOURNEY_WITH_CONTEXT, BANK_ACCOUNT_CONTEXT, null),
                Arguments.of(TEST_JOURNEY_WITH_SCOPE, null, IDENTITY_CHECK_SCOPE),
                Arguments.of(
                        TEST_JOURNEY_WITH_CONTEXT_AND_SCOPE,
                        BANK_ACCOUNT_CONTEXT,
                        IDENTITY_CHECK_SCOPE),
                Arguments.of(TEST_JOURNEY_WITH_EMPTY_CONTEXT, null, null));
    }

    @Test
    void getScoreTypeShouldReturnScoreType() throws HttpResponseExceptionWithErrorBody {
        ProcessRequest processRequest =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("scoreType", "fraud"))
                        .build();
        assertEquals("fraud", RequestHelper.getScoreType(processRequest));
    }

    @Test
    void getScoreTypeShouldThrowIfScoreTypeIsNull() {
        ProcessRequest processRequest = new ProcessRequest();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getScoreType(processRequest));

        assertEquals(SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_SCORE_TYPE.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getScoreThresholdShouldReturnScoreThreshold() throws HttpResponseExceptionWithErrorBody {
        ProcessRequest processRequest =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("scoreThreshold", 2))
                        .build();
        assertEquals(2, RequestHelper.getScoreThreshold(processRequest));
    }

    @Test
    void getScoreThresholdShouldThrowIfScoreThresholdIsNull() {
        ProcessRequest processRequest = new ProcessRequest();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getScoreThreshold(processRequest));

        assertEquals(SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_SCORE_THRESHOLD.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getDeleteOnlyGPG45VCsShouldReturnTrue() throws Exception {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("deleteOnlyGPG45VCs", true))
                        .build();

        assertTrue(RequestHelper.getDeleteOnlyGPG45VCs(request));
    }

    @Test
    void getDeleteOnlyGPG45VCsShouldReturnFalse() throws Exception {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("deleteOnlyGPG45VCs", false))
                        .build();

        assertFalse(RequestHelper.getDeleteOnlyGPG45VCs(request));
    }

    @Test
    void getIdentityTypeShouldReturnNew() throws Exception {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("identityType", "new"))
                        .build();

        assertEquals(IdentityType.NEW, RequestHelper.getIdentityType(request));
    }

    @Test
    void getIdentityTypeShouldReturnPending() throws Exception {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("identityType", "pending"))
                        .build();

        assertEquals(IdentityType.PENDING, RequestHelper.getIdentityType(request));
    }

    @Test
    void getIdentityTypeShouldReturnUpdate() throws Exception {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("identityType", "UPDATE"))
                        .build();

        assertEquals(IdentityType.UPDATE, RequestHelper.getIdentityType(request));
    }

    @Test
    void getIdentityTypeShouldThrowIfNull() {
        var lambdaInput = new HashMap<String, Object>();
        lambdaInput.put("identityType", null);
        ProcessRequest request =
                ProcessRequest.processRequestBuilder().lambdaInput(lambdaInput).build();

        HttpResponseExceptionWithErrorBody thrown =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getIdentityType(request));

        assertEquals(ErrorResponse.INVALID_IDENTITY_TYPE_PARAMETER, thrown.getErrorResponse());
    }

    @Test
    void getIdentityTypeShouldThrowIfInvalid() {
        var lambdaInput = new HashMap<String, Object>();
        lambdaInput.put("identityType", "invalid");
        ProcessRequest request =
                ProcessRequest.processRequestBuilder().lambdaInput(lambdaInput).build();

        HttpResponseExceptionWithErrorBody thrown =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getIdentityType(request));

        assertEquals(ErrorResponse.INVALID_IDENTITY_TYPE_PARAMETER, thrown.getErrorResponse());
    }

    @Test
    void getCoiCheckTypeShouldReturnCoiCheckType() throws Exception {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("checkType", STANDARD.name()))
                        .build();

        assertEquals(STANDARD, RequestHelper.getCoiCheckType(request));
    }

    @Test
    void getCoiCheckTypeShouldThrowIfMissingCheckType() {
        ProcessRequest request = ProcessRequest.processRequestBuilder().build();

        var thrown =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getCoiCheckType(request));
        assertEquals(MISSING_CHECK_TYPE, thrown.getErrorResponse());
    }

    @Test
    void getCoiCheckTypeShouldThrowIfUnknownCheckType() {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("checkType", "wat?"))
                        .build();

        var thrown =
                assertThrows(
                        UnknownCoiCheckTypeException.class,
                        () -> RequestHelper.getCoiCheckType(request));
        assertEquals("wat?", thrown.getCheckType());
    }

    @Test
    void getSessionCredentialsResetTypeShouldReturnResetType() throws Exception {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("resetType", NAME_ONLY_CHANGE.name()))
                        .build();

        assertEquals(NAME_ONLY_CHANGE, RequestHelper.getSessionCredentialsResetType(request));
    }

    @Test
    void getSessionCredentialsResetTypeShouldThrowIfMissingResetType() {
        ProcessRequest request = ProcessRequest.processRequestBuilder().build();

        var thrown =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getSessionCredentialsResetType(request));
        assertEquals(MISSING_RESET_TYPE, thrown.getErrorResponse());
    }

    @Test
    void getSessionCredentialsResetTypeShouldThrowIfUnknownResetType() {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("resetType", "nooo"))
                        .build();

        var thrown =
                assertThrows(
                        UnknownResetTypeException.class,
                        () -> RequestHelper.getSessionCredentialsResetType(request));
        assertEquals("nooo", thrown.getResetType());
    }

    @Test
    void getProcessIdentityTypeShouldReturnCandidateIdentityIfValid() throws Exception {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("identityType", CandidateIdentityType.NEW.name()))
                        .build();

        assertEquals(CandidateIdentityType.NEW, RequestHelper.getProcessIdentityType(request));
    }

    @Test
    void getProcessIdentityTypeThrowsIfMissingProcessIdentityType() {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("anotherTypeField", "something-else"))
                        .build();

        var thrown =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getProcessIdentityType(request));
        assertEquals(MISSING_PROCESS_IDENTITY_TYPE, thrown.getErrorResponse());
    }

    @Test
    void getProcessIdentityTypeShouldThrowIfUnknownResetType() {
        ProcessRequest request =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("identityType", "some-nonsense"))
                        .build();

        var thrown =
                assertThrows(
                        UnknownProcessIdentityTypeException.class,
                        () -> RequestHelper.getProcessIdentityType(request));
        assertEquals("some-nonsense", thrown.getProcessIdentityType());
    }
}
