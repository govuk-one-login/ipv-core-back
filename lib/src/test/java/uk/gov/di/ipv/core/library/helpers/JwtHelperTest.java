package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.SharedAttributes;
import uk.gov.di.ipv.core.library.domain.SharedAttributesResponse;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtHelperTest {

    public static final String BASE64_SIGNING_KEY =
            "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";

    private static final String BASE64_CERT = "MIIDZzCCAk+gAwIBAgIBATANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJVSzEXMBUGA1UECBMOR3JlYXRlciBMb25kb24xDzANBgNVBAcTBkxvbmRvbjEXMBUGA1UEChMOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsTA0dEUzEXMBUGA1UEAxMOTXkgY29tbW9uIG5hbWUwHhcNMjIwMTMxMTExNDM3WhcNMjMwMTMxMTExNDM3WjB3MQswCQYDVQQGEwJVSzEXMBUGA1UECBMOR3JlYXRlciBMb25kb24xDzANBgNVBAcTBkxvbmRvbjEXMBUGA1UEChMOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsTA0dEUzEXMBUGA1UEAxMOTXkgY29tbW9uIG5hbWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCRZHUZZOG6W9hrxx/qo8hl9c6rd/0HCed7Vd2DidJ2yRTjbMZ0q8S9OdxTO2H0Wrrt1r4k6RqRKDImdcRqsJKM8iamcS8kYnQHUdHaqnwcFkDtM29A/57V0by2H/fUJss5MqLCE6hBKnrNc/WrI5VCx2LNEe833yDM1fYDjh0CKJK8e0bXMRCTn1sl2wmmBucRaXIZa2msey6SpgxG7REuVsc+Y804yuZAOaTyFP485D8QMVjwl/KRGVich7XYaxTZI3N4KGpS0K9Ui0U+FwuCxsDDdABQ1B2acINZ1ookghLp3EsnpvUJlHw+rPvvqOd18D64TQIDm67O4jK+c4zAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADVrL7p+L5Y38LSMkIJF+fNTXN2xb0cFwn6fHLiD1Jpvq2LoMU18P1lBT4ZFsPFM8OPk58m6Nid8GVJpp+Pz/8a7Uhx3PfpB2uKzmpwBktBu5xpdE+DS/omxnlY91vAnCJaA3NdBYaDGavbs3J0rCR5DpH56hXikmtR3IzGYgrX3TJJghl6vWXZsW/J9nG5+W62SOX9hQUzj3rkXYKfcugODRAsBSC72zOgOU8+7MyDJkX9ndS6UOA5owUDonv75rVEDHNV/vcKrIrs43gmmcQ+PnxU7RwbCsUAN/si4emkR8zAdCQVvi0VFh9woikHOZvlXwm/GGINiLDi8E3kxL10=";

    @Mock
    private JWSSigner mockSigner;

    @Test
    void shouldCreateValidSignedJWT()
            throws JOSEException,
            ParseException, CertificateException {
        Base64URL signature = Base64URL.from("TEGWSkTIhCUUTik-C54XFoy7UkcH4EDVIZka2fPDUk_dzCqF4COacbWvOrd1WRrB34uzwE1ebZFLTkfXiFw1mJj7DMYnQS5DBxSIyTql0X3Qn6o8R50scMunErzfyiAkVfYT03jrY30fawZy5yYcDnOo_LOCmajQOTMQOwi5XTMfd3Jt7sALSNxjrpDTk35BLN4TaITsaSr1omzK3b6FbOENuQN83RJm32-u66T_f7Qxsqch-OJtg2XHZBTflT3VtOF07v8DPi6SUAxo0ECbiKckN3MuZg6swH2d2vIMG7fVdkHEqyUNYARwbMBqPM722qlY4daSDtvvcuFK6yGv4g==");

        when(mockSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(signature);
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.RS256));

        String dateOfBirth = "1969-20-07";
        String familyName = "Holmes";
        List<String> givenNames = List.of("Sherlock");
        Name name = new Name(givenNames, familyName);

        SharedAttributes sharedAttributes =
                new SharedAttributes.Builder().setName(name).setDateOfBirth("1969-20-07").build();

        SharedAttributesResponse sharedAttributesResponse =
                SharedAttributesResponse.from(List.of(sharedAttributes));

        SignedJWT signedJWT =
                JwtHelper.createSignedJwtFromObject(sharedAttributesResponse, mockSigner);
        JWTClaimsSet generatedClaims = signedJWT.getJWTClaimsSet();

        assertTrue(
                signedJWT.verify(
                        new RSASSAVerifier((RSAPublicKey) getCertificate(BASE64_CERT).getPublicKey())));


        assertEquals(List.of(dateOfBirth), generatedClaims.getClaim("dateOfBirths"));
        List<Map<String, Object>> names =
                (List<Map<String, Object>>) generatedClaims.getClaim("names");
        assertEquals(name.getFamilyName(), names.get(0).get("familyName"));
        assertEquals(
                name.getGivenNames().get(0),
                ((List<String>) names.get(0).get("givenNames")).get(0));
    }


    private Certificate getCertificate(String base64certificate) throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(base64certificate);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }
}
