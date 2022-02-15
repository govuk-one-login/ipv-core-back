package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.List;

public class ConfigurationServicePublicKeySelector implements ClientCredentialsSelector<Object> {

    public static final Logger LOGGER =
            LoggerFactory.getLogger(ConfigurationServicePublicKeySelector.class);

    private final ConfigurationService configurationService;

    public ConfigurationServicePublicKeySelector(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public List<Secret> selectClientSecrets(
            ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) {
        throw new UnsupportedOperationException("We don't do that round here...");
    }

    @Override
    public List<? extends PublicKey> selectPublicKeys(
            ClientID claimedClientID,
            ClientAuthenticationMethod authMethod,
            JWSHeader jwsHeader,
            boolean forceRefresh,
            Context context)
            throws InvalidClientException {
        try {
            return List.of(
                    configurationService
                            .getClientCertificate(claimedClientID.getValue())
                            .getPublicKey());
        } catch (CertificateException e) {
            throw new InvalidClientException(e.getMessage());
        }
    }
}
