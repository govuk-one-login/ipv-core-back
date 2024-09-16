package uk.gov.di.ipv.core.buildcrioauthrequest.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.SharedClaims;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.AddressAssertion;
import uk.gov.di.model.PersonWithDocuments;
import uk.gov.di.model.PersonWithIdentity;

import java.util.List;

import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;

public class SharedClaimsHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String SHARED_CLAIM_ATTR_NAME = "name";
    public static final String SHARED_CLAIM_ATTR_BIRTH_DATE = "birthDate";
    public static final String SHARED_CLAIM_ATTR_ADDRESS = "address";
    public static final String SHARED_CLAIM_ATTR_EMAIL = "emailAddress";
    public static final String SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD = "socialSecurityRecord";

    private SharedClaimsHelper() {}

    public static SharedClaims generateSharedClaims(
            String emailAddress, List<VerifiableCredential> vcs, List<String> allowedSharedClaims) {
        var sharedClaims = new SharedClaims();

        // Email address is provided separately in the session, not from a VC
        sharedClaims.setEmailAddress(emailAddress);

        // Other shared claims are added from successful VCs
        for (var vc : vcs) {
            if (VcHelper.isSuccessfulVc(vc)) {
                var credentialSubject = vc.getCredential().getCredentialSubject();

                if (credentialSubject instanceof PersonWithIdentity personWithIdentity
                        && personWithIdentity.getName() != null) {
                    sharedClaims.getName().addAll(personWithIdentity.getName());
                }
                if (credentialSubject instanceof PersonWithIdentity personWithIdentity
                        && personWithIdentity.getBirthDate() != null) {
                    sharedClaims.getBirthDate().addAll(personWithIdentity.getBirthDate());
                }
                if (ADDRESS.equals(vc.getCri())
                        && credentialSubject instanceof AddressAssertion addressAssertion
                        && addressAssertion.getAddress() != null) {
                    sharedClaims.getAddress().addAll(addressAssertion.getAddress());
                }
                if (credentialSubject instanceof PersonWithDocuments personWithDocuments
                        && personWithDocuments.getSocialSecurityRecord() != null) {
                    sharedClaims
                            .getSocialSecurityRecord()
                            .addAll(personWithDocuments.getSocialSecurityRecord());
                }
            }
        }

        LOGGER.info(
                LogHelper.buildLogMessage("Found shared claims")
                        .with("names", sharedClaims.getName().size())
                        .with("birthDates", sharedClaims.getBirthDate().size())
                        .with("addresses", sharedClaims.getAddress().size())
                        .with("emails", sharedClaims.getEmailAddress() == null ? 0 : 1)
                        .with(
                                "socialSecurityRecords",
                                sharedClaims.getSocialSecurityRecord().size()));

        stripDisallowedSharedClaims(sharedClaims, allowedSharedClaims);

        return sharedClaims;
    }

    private static void stripDisallowedSharedClaims(
            SharedClaims credentialsSharedClaims, List<String> allowedSharedAttr) {
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_NAME)) {
            credentialsSharedClaims.setName(null);
        }
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_BIRTH_DATE)) {
            credentialsSharedClaims.setBirthDate(null);
        }
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_ADDRESS)) {
            credentialsSharedClaims.setAddress(null);
        }
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_EMAIL)) {
            credentialsSharedClaims.setEmailAddress(null);
        }
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD)) {
            credentialsSharedClaims.setSocialSecurityRecord(null);
        }
    }
}
