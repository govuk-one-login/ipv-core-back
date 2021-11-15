package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import uk.gov.di.ipv.domain.gpg45.ConfidenceLevel;
import uk.gov.di.ipv.domain.gpg45.EvidenceScore;
import uk.gov.di.ipv.domain.gpg45.IdentityProfile;
import uk.gov.di.ipv.domain.gpg45.IdentityProfileIdentifier;
import uk.gov.di.ipv.dto.UserInfoDto;

import java.util.Collections;
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
        IdentityProfile identityProfile = IdentityProfile.builder()
                .identityProfileIdentifier(IdentityProfileIdentifier.H1A)
                .description("Test identity profile")
                .levelOfConfidence(ConfidenceLevel.MEDIUM)
                .evidenceScoreCriteria(Collections.singletonList(new EvidenceScore()))
                .build();

        Map<String, Object> userInfo = Map.of(
                "iss", ISSUER_URN,
                "aud", ORCHESTRATOR_URN,
                "sub", ORCHESTRATOR_URN,
                "identityProfile", identityProfile,
                "requestedLevelOfConfidence", ConfidenceLevel.MEDIUM);

        return new UserInfoDto(userInfo);
    }

    private boolean isTokenValid(AccessToken accessToken) {
        return true;
    }
}
