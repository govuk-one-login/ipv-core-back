package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import uk.gov.di.ipv.dto.UserInfoDto;

import java.util.Map;

public class UserInfoService {
    private static final String ISSUER_URN = "urn:di:ipv:ipv-core";
    private static final String ORCHESTRATOR_URN = "urn:di:ipv:orchestrator";

    public UserInfoDto handleUserInfo(AccessToken accessToken) {
        if (!isTokenValid(accessToken)) {
            throw new RuntimeException("Provided access token is not a valid token");
        }

        return createUserInfoResponse();
    }

    private UserInfoDto createUserInfoResponse() {
        Map<String, Object> userInfo =
                Map.of(
                        "iss", ISSUER_URN,
                        "aud", ORCHESTRATOR_URN,
                        "sub", ORCHESTRATOR_URN,
                        "identityProfile", "Test identity profile",
                        "requestedLevelOfConfidence", "Medium");

        return new UserInfoDto(userInfo);
    }

    private boolean isTokenValid(AccessToken accessToken) {
        return true;
    }
}
