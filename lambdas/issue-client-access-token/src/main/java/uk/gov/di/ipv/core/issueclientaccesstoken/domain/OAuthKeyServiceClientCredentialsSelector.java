package uk.gov.di.ipv.core.issueclientaccesstoken.domain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.List;

import static com.nimbusds.jose.JWSAlgorithm.ES256;

public class OAuthKeyServiceClientCredentialsSelector implements ClientCredentialsSelector<Object> {

    private final OAuthKeyService oAuthKeyService;

    public OAuthKeyServiceClientCredentialsSelector(OAuthKeyService oAuthKeyService) {
        this.oAuthKeyService = oAuthKeyService;
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

        var clientId = claimedClientID.getValue();
        var algorithm = jwsHeader.getAlgorithm();
        if (algorithm != ES256) {
            throw new InvalidClientException(
                    String.format(
                            "%s algorithm is not supported. Received from client ID '%s'",
                            algorithm, clientId));
        }

        try {
            return List.of(
                    oAuthKeyService.getClientSigningKey(clientId, jwsHeader).toECPublicKey());
        } catch (ParseException | JOSEException e) {
            throw new InvalidClientException(
                    String.format(
                            "Could not parse public key material for client ID '%s': %s",
                            clientId, e.getMessage()));
        }
    }
}
