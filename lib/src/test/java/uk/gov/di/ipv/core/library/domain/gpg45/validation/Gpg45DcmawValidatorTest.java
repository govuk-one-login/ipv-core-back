package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScores;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.DcmawCheckMethod;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45DcmawValidatorTest {

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        2,
                        1,
                        2,
                        Collections.singletonList(new DcmawCheckMethod()),
                        null,
                        Collections.emptyList());

        assertTrue(
                Gpg45DcmawValidator.isSuccessful(
                        credentialEvidenceItem, Collections.emptyMap(), 0));
    }

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredentialAndNullCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3, 2, 1, 2, Collections.singletonList(new DcmawCheckMethod()), null, null);

        assertTrue(
                Gpg45DcmawValidator.isSuccessful(
                        credentialEvidenceItem, Collections.emptyMap(), 0));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnInValidCredentialWithFailedCheckDetails() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        0,
                        1,
                        2,
                        null,
                        Collections.singletonList(new DcmawCheckMethod()),
                        Collections.emptyList());

        assertFalse(
                Gpg45DcmawValidator.isSuccessful(
                        credentialEvidenceItem, Collections.emptyMap(), 0));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnInValidCredentialWithIncorrectValidityScoreValue() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        0,
                        1,
                        2,
                        Collections.singletonList(new DcmawCheckMethod()),
                        null,
                        Collections.emptyList());

        assertFalse(
                Gpg45DcmawValidator.isSuccessful(
                        credentialEvidenceItem, Collections.emptyMap(), 0));
    }

    @Test
    void isSuccessfulShouldReturnTrueIfCredentialContainsCiWithinScoreThreshold() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        2,
                        1,
                        2,
                        Collections.singletonList(new DcmawCheckMethod()),
                        null,
                        List.of("D02"));
        Map<String, ContraIndicatorScores> scoresMap = new HashMap<>();
        scoresMap.put("D02", new ContraIndicatorScores("D02", 50, 0, null));

        assertTrue(Gpg45DcmawValidator.isSuccessful(credentialEvidenceItem, scoresMap, 100));
    }

    @Test
    void isSuccessfulShouldReturnFalseIfCredentialContainsCiExceedingScoreThreshold() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        2,
                        1,
                        2,
                        Collections.singletonList(new DcmawCheckMethod()),
                        null,
                        List.of("D02"));
        Map<String, ContraIndicatorScores> scoresMap = new HashMap<>();
        scoresMap.put("D02", new ContraIndicatorScores("D02", 150, 0, null));

        assertFalse(Gpg45DcmawValidator.isSuccessful(credentialEvidenceItem, scoresMap, 100));
    }
}
