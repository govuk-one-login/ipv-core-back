package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.nimbusds.jwt.SignedJWT;
import lombok.NoArgsConstructor;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
public class JwtParser {

    public List<SignedJWT> parseVerifiableCredentialJWTs(
            List<String> verifiableCredentialJWTStrings) throws ParseException {
        final List<SignedJWT> verifiableCredentials = new ArrayList<>();
        for (String verifiableCredentialString : verifiableCredentialJWTStrings) {
            verifiableCredentials.add(SignedJWT.parse(verifiableCredentialString));
        }
        return verifiableCredentials;
    }
}
