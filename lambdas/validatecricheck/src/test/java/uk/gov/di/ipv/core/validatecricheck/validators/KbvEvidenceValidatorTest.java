package uk.gov.di.ipv.core.validatecricheck.validators;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.validatecricheck.CriCheckValidationException;
import uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_KBV_VC_FAILED;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_KBV_VC_PASSED;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.CRI_ID_KBV;

class KbvEvidenceValidatorTest {
    private final CriCheckValidator criCheckValidator = new CriCheckValidator();

    @Test
    void returnsTrueForSuccessfulKbvCheck() throws CriCheckValidationException {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(SIGNED_KBV_VC_PASSED);
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_KBV);

        assertTrue(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void returnsFalseForKbvCheckWithLowVerificationScore() throws CriCheckValidationException {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(SIGNED_KBV_VC_FAILED);
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_KBV);

        assertFalse(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }
}
