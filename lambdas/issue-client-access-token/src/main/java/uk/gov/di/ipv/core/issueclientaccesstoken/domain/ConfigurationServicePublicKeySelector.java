package uk.gov.di.ipv.core.issueclientaccesstoken.domain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY;

public class ConfigurationServicePublicKeySelector implements ClientCredentialsSelector<Object> {

    private static final Base64.Decoder decoder = Base64.getDecoder();
    private static final String ES256 = "ES256";
    private static final String RS256 = "RS256";

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

        JWSAlgorithm algorithm = jwsHeader.getAlgorithm();
        String clientId = claimedClientID.getValue();
        String publicKeyMaterial =
                configurationService.getSsmParameter(
                        PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, clientId);

        try {
            switch (algorithm.toString()) {
                case ES256:
                    return List.of(ECKey.parse(publicKeyMaterial).toECPublicKey());
                case RS256:
                    return List.of(
                            CertificateFactory.getInstance("X.509")
                                    .generateCertificate(
                                            new ByteArrayInputStream(
                                                    decoder.decode(publicKeyMaterial)))
                                    .getPublicKey());
                default:
                    throw new InvalidClientException(
                            String.format(
                                    "%s algorithm is not supported. Received from client ID '%s'",
                                    algorithm, clientId));
            }
        } catch (ParseException
                | JOSEException
                | CertificateException
                | IllegalArgumentException e) {
            throw new InvalidClientException(
                    String.format(
                            "Could not parse public key material for client ID '%s': %s",
                            clientId, e.getMessage()));
        }
    }
}
