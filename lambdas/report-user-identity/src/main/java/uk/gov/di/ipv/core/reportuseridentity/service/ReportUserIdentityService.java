package uk.gov.di.ipv.core.reportuseridentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.OperationalProfile;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.PersonWithDocuments;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.util.CollectionUtils.isNotEmpty;
import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.enums.Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;

public class ReportUserIdentityService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;

    public ReportUserIdentityService(Gpg45ProfileEvaluator gpg45ProfileEvaluator) {
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
    }

    @ExcludeFromGeneratedCoverageReport
    public ReportUserIdentityService() {
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
    }

    public Optional<Vot> getStrongestAttainedVotForVtr(List<VerifiableCredential> vcs)
            throws ParseException {
        for (Vot requestedVot : SUPPORTED_VOTS_BY_DESCENDING_STRENGTH) {
            boolean requestedVotAttained;
            if (requestedVot.getProfileType().equals(GPG45)) {
                requestedVotAttained =
                        achievedWithGpg45Profile(
                                requestedVot, VcHelper.filterVCBasedOnProfileType(vcs, GPG45));
            } else {
                requestedVotAttained = hasOperationalProfileVc(requestedVot, vcs);
            }

            if (requestedVotAttained) {
                return Optional.of(requestedVot);
            }
        }
        return Optional.empty();
    }

    private boolean achievedWithGpg45Profile(Vot requestedVot, List<VerifiableCredential> vcs) {
        Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(vcs);
        Optional<Gpg45Profile> matchedGpg45Profile =
                gpg45ProfileEvaluator.getFirstMatchingProfile(
                        gpg45Scores, requestedVot.getSupportedGpg45Profiles());

        // Successful match
        if (matchedGpg45Profile.isPresent()) {
            LOGGER.info(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "GPG45 profile matched")
                            .with(LOG_VOT.getFieldName(), requestedVot));
            return true;
        }
        return false;
    }

    private boolean hasOperationalProfileVc(Vot requestedVot, List<VerifiableCredential> vcs)
            throws ParseException {
        for (var vc : vcs) {
            String credentialVot = vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME);
            Optional<String> matchedOperationalProfile =
                    requestedVot.getSupportedOperationalProfiles().stream()
                            .map(OperationalProfile::name)
                            .filter(profileName -> profileName.equals(credentialVot))
                            .findFirst();

            // Successful match
            if (matchedOperationalProfile.isPresent()) {
                LOGGER.info(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Operational profile matched")
                                .with(LOG_VOT.getFieldName(), requestedVot));
                return true;
            }
        }
        return false;
    }

    public List<String> getIdentityConstituent(List<VerifiableCredential> tacticalVcs) {
        return tacticalVcs.stream()
                .map(
                        vc -> {
                            if (vc.getCri().equals(Cri.DCMAW)) {
                                var credentialSubject = vc.getCredential().getCredentialSubject();
                                if (credentialSubject instanceof PersonWithDocuments person) {
                                    if (isNotEmpty(person.getBankAccount())) {
                                        return "dcmaw-bankAccount";
                                    } else if (isNotEmpty(person.getDrivingPermit())) {
                                        return "dcmaw-drivingPermit";
                                    } else if (isNotEmpty(person.getIdCard())) {
                                        return "dcmaw-idCard";
                                    } else if (isNotEmpty(person.getPassport())) {
                                        return "dcmaw-passport";
                                    } else if (isNotEmpty(person.getResidencePermit())) {
                                        return "dcmaw-residencePermit";
                                    } else if (isNotEmpty(person.getSocialSecurityRecord())) {
                                        return "dcmaw-socialSecurityRecord";
                                    }
                                }
                                return "dcmaw";
                            } else {
                                return vc.getCri().getId();
                            }
                        })
                .toList();
    }
}
