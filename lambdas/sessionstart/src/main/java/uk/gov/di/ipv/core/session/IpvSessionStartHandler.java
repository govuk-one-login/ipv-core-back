package uk.gov.di.ipv.core.session;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.JarValidationException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.KmsRsaDecrypter;
import uk.gov.di.ipv.core.library.validation.JarValidator;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

public class IpvSessionStartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(IpvSessionStartHandler.class.getName());
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String IPV_SESSION_ID_KEY = "ipvSessionId";

    private final ConfigurationService configurationService;
    private final IpvSessionService ipvSessionService;
    private final KmsRsaDecrypter kmsRsaDecrypter;
    private final JarValidator jarValidator;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public IpvSessionStartHandler() {
        this.configurationService = new ConfigurationService();
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.kmsRsaDecrypter = new KmsRsaDecrypter(configurationService.getJarKmsEncryptionKeyId());
        this.jarValidator = new JarValidator(kmsRsaDecrypter, configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
    }

    public IpvSessionStartHandler(
            IpvSessionService ipvSessionService,
            ConfigurationService configurationService,
            KmsRsaDecrypter kmsRsaDecrypter,
            JarValidator jarValidator,
            AuditService auditService) {
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
        this.kmsRsaDecrypter = kmsRsaDecrypter;
        this.jarValidator = jarValidator;
        this.auditService = auditService;
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            ClientSessionDetailsDto clientSessionDetails =
                    objectMapper.readValue(input.getBody(), ClientSessionDetailsDto.class);

            Optional<ErrorResponse> error = validateClientSessionDetails(clientSessionDetails);

            if (error.isPresent()) {
                LOGGER.error("Validation of the client session details failed");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, error.get());
            }

            if (StringUtils.isNotBlank(clientSessionDetails.getRequest())) {
                SignedJWT signedJWT = decryptRequest(clientSessionDetails.getRequest());
                jarValidator.validateRequestJwt(signedJWT, clientSessionDetails.getClientId());
            }

            String ipvSessionId = ipvSessionService.generateIpvSession(clientSessionDetails);

            auditService.sendAuditEvent(AuditEventTypes.IPV_JOURNEY_START);

            Map<String, String> response = Map.of(IPV_SESSION_ID_KEY, ipvSessionId);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
        } catch (IllegalArgumentException | JsonProcessingException e) {
            LOGGER.error(
                    "Failed to parse the request body into a ClientSessionDetailsDto object", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse the decrypted JWE because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (JarValidationException e) {
            LOGGER.error("Jar validation failed because: {}", e.getErrorObject().getDescription());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    private Optional<ErrorResponse> validateClientSessionDetails(
            ClientSessionDetailsDto clientSessionDetailsDto) {
        boolean isInvalid = false;
        if (StringUtils.isBlank(clientSessionDetailsDto.getResponseType())) {
            LOGGER.warn("Missing response_type query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientSessionDetailsDto.getClientId())) {
            LOGGER.warn("Missing client_id query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientSessionDetailsDto.getRedirectUri())) {
            LOGGER.warn("Missing redirect_uri query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientSessionDetailsDto.getScope())) {
            LOGGER.warn("Missing scope query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientSessionDetailsDto.getState())) {
            LOGGER.warn("Missing state query parameter");
            isInvalid = true;
        }

        if (isInvalid) {
            return Optional.of(ErrorResponse.INVALID_SESSION_REQUEST);
        }
        return Optional.empty();
    }

    private SignedJWT decryptRequest(String jarString)
            throws ParseException, JarValidationException {
        try {
            JWEObject jweObject = JWEObject.parse(jarString);
            return jarValidator.decryptJWE(jweObject);
        } catch (ParseException e) {
            LOGGER.info("The JAR is not currently encrypted. Skipping the decryption step.");
            return SignedJWT.parse(jarString);
        }
    }
}
