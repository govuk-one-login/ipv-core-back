package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.UserInfoDto;
import uk.gov.di.ipv.service.UserInfoService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserInfoHandlerTest {
    private final Context context = mock(Context.class);
    private final UserInfoService userInfoService = mock(UserInfoService.class);

    private UserInfoHandler userInfoHandler;
    private UserInfoDto userInfoDto;

    ObjectMapper objectMapper = new ObjectMapper();
    Map responseBody = new HashMap<>();

    @BeforeEach
    public void setUp() {
        Map<String, Object> userInfo = new HashMap<>();

        userInfo.put("iss", "Test iss");
        userInfo.put("aud", "Test aud");
        userInfo.put("sub", "Test sub");
        userInfo.put("identityProfile", "Test identity profile");
        userInfo.put("requestedLevelOfConfidence", "Medium");

        userInfoDto = new UserInfoDto(userInfo);
        when(userInfoService.handleUserInfo(any())).thenReturn(userInfoDto);

        userInfoHandler = new UserInfoHandler(userInfoService);
    }

    @Test
    public void shouldReturn200OnSuccessfulUserInfoRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers = Collections.singletonMap("Authorization", "Bearer " + accessToken);

        event.setHeaders(headers);
        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, context);

        assertEquals(200, response.getStatusCode());
    }

    @Test
    public void shouldReturnUserInfoObjectOnSuccessfulUserInfoRequest() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers = Collections.singletonMap("Authorization", "Bearer " + accessToken);

        event.setHeaders(headers);
        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(userInfoDto.getJsonAttributes().get("requestedLevelOfConfidence").toString(), responseBody.get("requestedLevelOfConfidence"));
        assertEquals(userInfoDto.getJsonAttributes().get("iss").toString(), responseBody.get("iss"));
        assertEquals(userInfoDto.getJsonAttributes().get("aud").toString(), responseBody.get("aud"));
        assertEquals(userInfoDto.getJsonAttributes().get("sub").toString(), responseBody.get("sub"));
    }

    @Test
    public void shouldReturnErrorTokenResponseWhenTokenIsNull() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", null);
        event.setHeaders(headers);
        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, context);
        responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MissingAccessToken.getCode(), responseBody.get("code"));
        assertEquals("Missing access token from user info request", responseBody.get("message"));
    }

    @Test
    public void shouldReturnErrorTokenResponseWhenTokenIsInvalid() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", "11111111");
        event.setHeaders(headers);
        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, context);
        responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.FailedToParseAccessToken.getCode(), responseBody.get("code"));
        assertEquals("Failed to parse access token", responseBody.get("message"));

    }
}