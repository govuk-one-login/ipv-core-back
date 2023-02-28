package uk.gov.di.ipv.core.builddebugcredentialdata;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class BuildDebugCredentialDataHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final UserIdentityService userIdentityService;
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private static final Logger LOGGER = LogManager.getLogger();

    public BuildDebugCredentialDataHandler(
            UserIdentityService userIdentityService,
            ConfigService configService,
            IpvSessionService ipvSessionService) {
        this.userIdentityService = userIdentityService;
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildDebugCredentialDataHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(input);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientSessionDetailsDto.getGovukSigninJourneyId());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK,
                    getUserIssuedDebugCredentials(clientSessionDetailsDto.getUserId()));
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        }
    }

    public Map<String, String> getUserIssuedDebugCredentials(String userId) {
        var vcStoreItems = userIdentityService.getVcStoreItems(userId);

        Map<String, String> userIssuedDebugCredentials = new HashMap<>();
        Gson gson = new Gson();

        vcStoreItems.forEach(
                vcStoreItem -> {
                    DebugCredentialAttributes attributes =
                            new DebugCredentialAttributes(
                                    vcStoreItem.getUserId(),
                                    vcStoreItem.getDateCreated().toString());
                    UserIssuedDebugCredential debugCredential =
                            new UserIssuedDebugCredential(attributes);

                    try {
                        JWTClaimsSet jwtClaimsSet =
                                SignedJWT.parse(vcStoreItem.getCredential()).getJWTClaimsSet();
                        JSONObject vcClaim = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
                        if (vcClaim == null || isNotPopulatedJsonArray(vcClaim.get(VC_EVIDENCE))) {
                            LOGGER.error("Evidence not found in verifiable credential");
                        } else {
                            JSONArray evidenceArray = ((JSONArray) vcClaim.get(VC_EVIDENCE));
                            debugCredential.setEvidence((Map<String, Object>) evidenceArray.get(0));
                        }
                    } catch (ParseException e) {
                        LOGGER.error("Failed to parse credential JSON for the debug page");
                    }

                    String debugCredentialJson = gson.toJson(debugCredential);

                    userIssuedDebugCredentials.put(
                            vcStoreItem.getCredentialIssuer(), debugCredentialJson);
                });

        return userIssuedDebugCredentials;
    }

    private boolean isNotPopulatedJsonArray(Object input) {
        return !(input instanceof JSONArray)
                || ((JSONArray) input).isEmpty()
                || !(((JSONArray) input).get(0) instanceof JSONObject);
    }
}
