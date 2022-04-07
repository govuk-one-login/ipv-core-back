package uk.gov.di.ipv.core.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.SharedAttributes;
import uk.gov.di.ipv.core.library.domain.SharedAttributesResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.KmsEs256Signer;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;

public class SharedAttributesHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(SharedAttributesHandler.class);

    public static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    public static final int BAD_REQUEST = 400;
    public static final int OK = 200;
    public static final String SHARED_CLAIMS = "shared_claims";

    private final UserIdentityService userIdentityService;
    private final ObjectMapper mapper = new ObjectMapper();
    private final JWSSigner signer;

    public SharedAttributesHandler(UserIdentityService userIdentityService, JWSSigner signer) {
        this.userIdentityService = userIdentityService;
        this.signer = signer;
    }

    @ExcludeFromGeneratedCoverageReport
    public SharedAttributesHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.signer = new KmsEs256Signer(configurationService.getSigningKeyId());
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            String ipvSessionId = getIpvSessionId(input.getHeaders());
            SharedAttributesResponse sharedAttributesResponse = getSharedAttributes(ipvSessionId);

            SignedJWT signedJWT = signSharedAttributesResponse(sharedAttributesResponse);

            return ApiGatewayResponseGenerator.proxyJoseResponse(OK, signedJWT.serialize());
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        }
    }

    @Tracing
    private SharedAttributesResponse getSharedAttributes(String ipvSessionId)
            throws HttpResponseExceptionWithErrorBody {
        Map<String, String> credentials =
                userIdentityService.getUserIssuedCredentials(ipvSessionId);

        List<SharedAttributes> sharedAttributes = new ArrayList<>();
        for (String credential : credentials.values()) {
            try {
                JsonNode credentialSubject =
                        mapper.readTree(SignedJWT.parse(credential).getPayload().toString())
                                .path(VC_CLAIM)
                                .path(VC_CREDENTIAL_SUBJECT);
                if (credentialSubject.isMissingNode()) {
                    LOGGER.error("Credential subject missing from verified credential");
                    throw new HttpResponseExceptionWithErrorBody(
                            500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
                }
                sharedAttributes.add(
                        mapper.readValue(credentialSubject.toString(), SharedAttributes.class));
            } catch (JsonProcessingException e) {
                LOGGER.error("Failed to get Shared Attributes: {}", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GET_SHARED_ATTRIBUTES);
            } catch (ParseException e) {
                LOGGER.error("Failed to parse issued credentials: {}", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
            }
        }
        return SharedAttributesResponse.from(sharedAttributes);
    }

    @Tracing
    private SignedJWT signSharedAttributesResponse(
            SharedAttributesResponse sharedAttributesResponse)
            throws HttpResponseExceptionWithErrorBody {
        try {
            return JwtHelper.createSignedJwtFromObject(
                    Map.of(SHARED_CLAIMS, sharedAttributesResponse), signer);
        } catch (JOSEException e) {
            LOGGER.error("Failed to sign Shared Attributes: {}", e.getMessage());
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_SIGN_SHARED_ATTRIBUTES);
        }
    }

    private String getIpvSessionId(Map<String, String> headers)
            throws HttpResponseExceptionWithErrorBody {
        String ipvSessionId = RequestHelper.getHeaderByKey(headers, IPV_SESSION_ID_HEADER_KEY);
        if (ipvSessionId == null) {
            LOGGER.error("{} not present in header", IPV_SESSION_ID_HEADER_KEY);
            throw new HttpResponseExceptionWithErrorBody(
                    BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }
        return ipvSessionId;
    }
}
