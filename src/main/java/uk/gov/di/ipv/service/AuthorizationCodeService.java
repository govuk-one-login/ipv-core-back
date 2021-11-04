package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;

public class AuthorizationCodeService {

    public AuthorizationCode generateAuthorisationCode() {
        return new AuthorizationCode();
    }
}
