package uk.gov.di.ipv.core.buildcrioauthrequest.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.SharedClaims;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.NameHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.AddressAssertion;
import uk.gov.di.model.PersonWithDocuments;
import uk.gov.di.model.PersonWithIdentity;

import java.util.List;
import java.util.Set;

import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;

public class SharedClaimsHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String SHARED_CLAIM_ATTR_NAME = "name";
    public static final String SHARED_CLAIM_ATTR_BIRTH_DATE = "birthDate";
    public static final String SHARED_CLAIM_ATTR_ADDRESS = "address";
    public static final String SHARED_CLAIM_ATTR_EMAIL = "emailAddress";
    public static final String SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD = "socialSecurityRecord";
    public static final String SHARED_CLAIM_ATTR_DRIVING_PERMIT = "drivingPermit";

    private SharedClaimsHelper() {}

    public static SharedClaims generateSharedClaims(
            String emailAddress,
            List<VerifiableCredential> vcs,
            List<String> allowedSharedClaims,
            Cri targetCri) {
        var sharedClaims = new SharedClaims();

        // Email address is provided separately in the session, not from a VC
        sharedClaims.setEmailAddress(emailAddress);

        // Other shared claims are added from successful VCs
        vcs.stream()
                // If the target CRI is the Driving Licence CRI, we filter out
                // any driving licence VCs so they aren't included in the shared claims.
                // This is to handle the case where a user has a DL and DCMAW VC with driving permit
                // details and needs to go through an authoritative source check with the DL CRI. In
                // this scenario, we only want to share the driving permit details from the DCMAW
                // VC.
                .filter(
                        vc ->
                                !(Cri.DRIVING_LICENCE.equals(targetCri)
                                        && Cri.DRIVING_LICENCE.equals(vc.getCri())))
                .filter(VcHelper::isSuccessfulVc)
                .forEach(vc -> addSharedClaimsFromVc(sharedClaims, vc));

        // Deduplicate name with case insensitivity
        sharedClaims.setName(NameHelper.deduplicateNames(sharedClaims.getName()));

        stripDisallowedSharedClaims(sharedClaims, allowedSharedClaims);

        LOGGER.info(
                LogHelper.buildLogMessage("Found shared claims")
                        .with("names", safeSize(sharedClaims.getName()))
                        .with("birthDates", safeSize(sharedClaims.getBirthDate()))
                        .with("addresses", safeSize(sharedClaims.getAddress()))
                        .with("emails", sharedClaims.getEmailAddress() != null ? 1 : 0)
                        .with(
                                "socialSecurityRecords",
                                safeSize(sharedClaims.getSocialSecurityRecord()))
                        .with("drivingPermits", safeSize(sharedClaims.getDrivingPermit())));

        return sharedClaims;
    }

    private static int safeSize(Set<?> set) {
        return set != null ? set.size() : 0;
    }

    private static void addSharedClaimsFromVc(SharedClaims sharedClaims, VerifiableCredential vc) {
        var credentialSubject = vc.getCredential().getCredentialSubject();
        var vcCri = vc.getCri();

        if (credentialSubject instanceof PersonWithIdentity personWithIdentity
                && personWithIdentity.getName() != null) {
            sharedClaims.getName().addAll(personWithIdentity.getName());
        }
        if (credentialSubject instanceof PersonWithIdentity personWithIdentity
                && personWithIdentity.getBirthDate() != null) {
            sharedClaims.getBirthDate().addAll(personWithIdentity.getBirthDate());
        }
        if (ADDRESS.equals(vcCri)
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
        if (credentialSubject instanceof PersonWithDocuments personWithDocuments
                && personWithDocuments.getDrivingPermit() != null) {
            sharedClaims.getDrivingPermit().addAll(personWithDocuments.getDrivingPermit());
        }
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
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_DRIVING_PERMIT)) {
            credentialsSharedClaims.setDrivingPermit(null);
        }
    }
}
