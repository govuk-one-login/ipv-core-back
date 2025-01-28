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
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.PersonWithDocuments;
import uk.gov.di.model.PersonWithIdentity;

import java.util.HashMap;
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
            String emailAddress, List<VerifiableCredential> vcs, List<String> allowedSharedClaims) {
        var sharedClaims = new SharedClaims();
        var sharedDrivingPermitsMappedToVc = new HashMap<Cri, List<DrivingPermitDetails>>();

        // Email address is provided separately in the session, not from a VC
        sharedClaims.setEmailAddress(emailAddress);

        // Other shared claims are added from successful VCs
        vcs.stream()
                .filter(VcHelper::isSuccessfulVc)
                .forEach(
                        vc ->
                                addSharedClaimsFromVc(
                                        sharedClaims, vc, sharedDrivingPermitsMappedToVc));

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

    private static void addSharedClaimsFromVc(SharedClaims sharedClaims, VerifiableCredential vc, HashMap<Cri, List<DrivingPermitDetails>> drivingPermitsSharedClaims) {
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
                && personWithDocuments.getDrivingPermit() != null
                // skip adding driving permit from DL VC if there is already a drivingPermit from
                // DCMAW
                && !((drivingPermitsSharedClaims.containsKey(Cri.DCMAW)
                                || drivingPermitsSharedClaims.containsKey(Cri.DCMAW_ASYNC))
                        && Cri.DRIVING_LICENCE.equals(vcCri))) {

            // De-duplicate driving permit shared claims by removing existing DL VC driving permit
            // shared claim and
            // replacing with DCMAW VC driving permit instead.
            if (((Cri.DCMAW.equals(vcCri) || Cri.DCMAW_ASYNC.equals(vcCri))
                    && drivingPermitsSharedClaims.containsKey(Cri.DRIVING_LICENCE))) {
                drivingPermitsSharedClaims
                        .get(Cri.DRIVING_LICENCE)
                        .forEach(sharedClaims.getDrivingPermit()::remove);
                drivingPermitsSharedClaims.remove(Cri.DRIVING_LICENCE);
            }

            drivingPermitsSharedClaims.put(vcCri, personWithDocuments.getDrivingPermit());
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
