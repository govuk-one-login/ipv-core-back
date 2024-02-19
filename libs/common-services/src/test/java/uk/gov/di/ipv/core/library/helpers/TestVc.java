package uk.gov.di.ipv.core.library.helpers;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.NameParts;

import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_FAMILY_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_GIVEN_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@Jacksonized
public class TestVc {
    @Builder.Default
    private String[] type = {VERIFIABLE_CREDENTIAL_TYPE, IDENTITY_CHECK_CREDENTIAL_TYPE};

    private TestCredentialSubject credentialSubject;
    private List<Map<String, Object>> evidence;

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    @Builder
    public static class TestCredentialSubject {
        @Builder.Default
        private List<NameParts> name =
                List.of(
                        new NameParts("KENNETH", VC_GIVEN_NAME),
                        new NameParts("DECERQUEIRA", VC_FAMILY_NAME));

        @Builder.Default private List<BirthDate> birthDate = List.of(new BirthDate("1965-07-08"));

        @Builder.Default
        private List<Object> passport =
                List.of(
                        Map.of(
                                "documentNumber", "321654987",
                                "icaoIssuerCode", "GBR",
                                "expiryDate", "2030-01-01"));
    }
}
