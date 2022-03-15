package uk.gov.di.ipv.core.sessionend;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.AuthRequestValidator;
import uk.gov.di.ipv.core.sessionend.domain.ClientResponse;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SessionEndHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SessionEndHandler.class);
    private static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";

    private final AuthorizationCodeService authorizationCodeService;
    private final IpvSessionService sessionService;
    private final ConfigurationService configurationService;
    private final AuthRequestValidator authRequestValidator;

    @ExcludeFromGeneratedCoverageReport
    public SessionEndHandler() {
        this.configurationService = new ConfigurationService();
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
        this.sessionService = new IpvSessionService(configurationService);
        this.authRequestValidator = new AuthRequestValidator(configurationService);
    }

    public SessionEndHandler(
            AuthorizationCodeService authorizationCodeService,
            IpvSessionService sessionService,
            ConfigurationService configurationService,
            AuthRequestValidator authRequestValidator) {
        this.authorizationCodeService = authorizationCodeService;
        this.sessionService = sessionService;
        this.configurationService = configurationService;
        this.authRequestValidator = authRequestValidator;
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        String ipvSessionId =
                RequestHelper.getHeaderByKey(input.getHeaders(), IPV_SESSION_ID_HEADER_KEY);

        IpvSessionItem ipvSessionItem = sessionService.getIpvSession(ipvSessionId);

        Map<String, List<String>> authParameters =
                getAuthParamsAsMap(ipvSessionItem.getClientSessionDetails());

        var validationResult =
                authRequestValidator.validateRequest(authParameters, input.getHeaders());
        if (!validationResult.isValid()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, validationResult.getError());
        }

        AuthenticationRequest authenticationRequest;
        try {
            authenticationRequest = AuthenticationRequest.parse(authParameters);
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }

        AuthorizationCode authorizationCode = authorizationCodeService.generateAuthorizationCode();

        authorizationCodeService.persistAuthorizationCode(
                authorizationCode.getValue(),
                ipvSessionId,
                authenticationRequest.getRedirectionURI().toString());

        ClientResponse clientResponse =
                new ClientResponse(
                        ipvSessionItem.getClientSessionDetails().getRedirectUri(),
                        authorizationCode.getValue());

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, clientResponse);
    }

    @Tracing
    private Map<String, List<String>> getAuthParamsAsMap(
            ClientSessionDetailsDto clientSessionDetailsDto) {
        if (clientSessionDetailsDto != null) {
            Map<String, List<String>> authParams = new HashMap<>();
            authParams.put(
                    AuthRequestValidator.RESPONSE_TYPE_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getResponseType()));
            authParams.put(
                    AuthRequestValidator.CLIENT_ID_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getClientId()));
            authParams.put(
                    AuthRequestValidator.REDIRECT_URI_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getRedirectUri()));
            authParams.put(
                    AuthRequestValidator.SCOPE_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getScope()));
            authParams.put(
                    AuthRequestValidator.STATE_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getState()));

            return authParams;
        }

        return Collections.emptyMap();
    }
}
