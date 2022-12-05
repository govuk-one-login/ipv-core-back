package uk.gov.di.ipv.core.builddebugcredentialdata;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.builddebugcredentialdata.TestFixtures.SIGNED_VC_1;
import static uk.gov.di.ipv.core.builddebugcredentialdata.TestFixtures.SIGNED_VC_2;

@ExtendWith(MockitoExtension.class)
public class BuildDebugCredentialDataHandlerTest {

    @Mock private Context mockContext;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private IpvSessionService mockIpvSessionService;

    private final Gson gson = new Gson();

    @Test
    void shouldReturn200OnSuccessfulRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String ipvSessionId = "a-session-id";
        String userId = "a-user-id";
        event.setHeaders(Map.of(RequestHelper.IPV_SESSION_ID_HEADER, ipvSessionId));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ClientSessionDetailsDto clientSessionDetailsDto = new ClientSessionDetailsDto();
        clientSessionDetailsDto.setUserId(userId);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(ipvSessionId)).thenReturn(ipvSessionItem);

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createUserIssuedCredentialsItem(
                                userId,
                                "criOne",
                                SIGNED_VC_1,
                                Instant.parse("2022-01-25T12:28:56.414849Z")),
                        createUserIssuedCredentialsItem(
                                userId,
                                "criTwo",
                                SIGNED_VC_2,
                                Instant.parse("2022-01-25T12:28:56.414849Z")));

        when(mockUserIdentityService.getVcStoreItems(userId)).thenReturn(vcStoreItems);
        BuildDebugCredentialDataHandler buildDebugCredentialDataHandler =
                new BuildDebugCredentialDataHandler(
                        mockUserIdentityService, mockConfigurationService, mockIpvSessionService);

        APIGatewayProxyResponseEvent response =
                buildDebugCredentialDataHandler.handleRequest(event, mockContext);

        assertEquals(200, response.getStatusCode());

        var gson = new Gson();
        Map<String, String> map = gson.fromJson(response.getBody(), Map.class);
        assertEquals(
                "{\"attributes\":{\"userId\":\"a-user-id\",\"dateCreated\":\"2022-01-25T12:28:56.414849Z\"},\"evidence\":{\"validityScore\":2,\"strengthScore\":4,\"txn\":\"1e0f28c5-6329-46f0-bf0e-833cb9b58c9e\",\"type\":\"IdentityCheck\"}}",
                map.get("criOne"));
        assertEquals(
                "{\"attributes\":{\"userId\":\"a-user-id\",\"dateCreated\":\"2022-01-25T12:28:56.414849Z\"},\"evidence\":{\"txn\":\"some-uuid\",\"identityFraudScore\":1,\"type\":\"CriStubCheck\"}}",
                map.get("criTwo"));
    }

    @Test
    void shouldReturn400IfNoSessionId() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        BuildDebugCredentialDataHandler buildDebugCredentialDataHandler =
                new BuildDebugCredentialDataHandler(
                        mockUserIdentityService, mockConfigurationService, mockIpvSessionService);

        APIGatewayProxyResponseEvent response =
                buildDebugCredentialDataHandler.handleRequest(event, mockContext);

        assertEquals(400, response.getStatusCode());
    }

    @Test
    void shouldReturn400IfSessionIdIsEmptyString() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(RequestHelper.IPV_SESSION_ID_HEADER, ""));
        BuildDebugCredentialDataHandler buildDebugCredentialDataHandler =
                new BuildDebugCredentialDataHandler(
                        mockUserIdentityService, mockConfigurationService, mockIpvSessionService);

        APIGatewayProxyResponseEvent response =
                buildDebugCredentialDataHandler.handleRequest(event, mockContext);

        assertEquals(400, response.getStatusCode());
    }

    private VcStoreItem createUserIssuedCredentialsItem(
            String userId, String credentialIssuer, String credential, Instant dateCreated) {
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId(userId);
        vcStoreItem.setCredentialIssuer(credentialIssuer);
        vcStoreItem.setCredential(credential);
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }
}
