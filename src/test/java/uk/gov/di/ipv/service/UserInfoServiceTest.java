package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.dto.UserInfoDto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class UserInfoServiceTest {

    @Test
    public void whenValidTokenShouldReturnUserInfo() {
        UserInfoService userInfoService = new UserInfoService();
        AccessToken accessToken = new BearerAccessToken();

        UserInfoDto userInfo = userInfoService.handleUserInfo(accessToken);
        assertNotNull(userInfo);
        assertEquals("urn:di:ipv:ipv-core", userInfo.getJsonAttributes().get("iss"));
        assertEquals("urn:di:ipv:orchestrator", userInfo.getJsonAttributes().get("sub"));
    }
}