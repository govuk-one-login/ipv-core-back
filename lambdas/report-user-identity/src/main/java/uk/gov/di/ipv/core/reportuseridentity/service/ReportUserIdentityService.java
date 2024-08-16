package uk.gov.di.ipv.core.reportuseridentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.PersonWithDocuments;

import java.util.List;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.util.CollectionUtils.isNotEmpty;
import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.enums.Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;

public class ReportUserIdentityService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;

    @ExcludeFromGeneratedCoverageReport
    public ReportUserIdentityService(Gpg45ProfileEvaluator gpg45ProfileEvaluator) {
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
    }

    @ExcludeFromGeneratedCoverageReport
    public ReportUserIdentityService() {
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
    }

    public Optional<Vot> getStrongestAttainedVotForCredentials(List<VerifiableCredential> vcs) {
        Gpg45Scores gpg45Scores =
                gpg45ProfileEvaluator.buildScore(VcHelper.filterVCBasedOnProfileType(vcs, GPG45));
        // Filter out since currently no operational profile in prod
        for (Vot votToCheck :
                SUPPORTED_VOTS_BY_DESCENDING_STRENGTH.stream()
                        .filter(vot -> vot.getProfileType().equals(GPG45))
                        .toList()) {
            if (achievedWithGpg45Profile(votToCheck, gpg45Scores)) {
                return Optional.of(votToCheck);
            }
        }
        return Optional.empty();
    }

    public List<String> getIdentityConstituent(List<VerifiableCredential> tacticalVcs) {
        return tacticalVcs.stream()
                .map(
                        vc -> {
                            Cri cri = vc.getCri();
                            if (cri.equals(Cri.DCMAW) || cri.equals(Cri.F2F)) {
                                var credentialSubject = vc.getCredential().getCredentialSubject();
                                if (credentialSubject instanceof PersonWithDocuments person) {
                                    if (isNotEmpty(person.getBankAccount())) {
                                        return cri.getId() + "-bankAccount";
                                    } else if (isNotEmpty(person.getDrivingPermit())) {
                                        return cri.getId() + "-drivingPermit";
                                    } else if (isNotEmpty(person.getIdCard())) {
                                        return cri.getId() + "-idCard";
                                    } else if (isNotEmpty(person.getPassport())) {
                                        return cri.getId() + "-passport";
                                    } else if (isNotEmpty(person.getResidencePermit())) {
                                        return cri.getId() + "-residencePermit";
                                    } else if (isNotEmpty(person.getSocialSecurityRecord())) {
                                        return cri.getId() + "-socialSecurityRecord";
                                    }
                                }
                            }
                            return cri.getId();
                        })
                .sorted()
                .toList();
    }

    private boolean achievedWithGpg45Profile(Vot votToCheck, Gpg45Scores gpg45Scores) {
        Optional<Gpg45Profile> matchedGpg45Profile =
                gpg45ProfileEvaluator.getFirstMatchingProfile(
                        gpg45Scores, votToCheck.getSupportedGpg45Profiles());

        // Successful match
        if (matchedGpg45Profile.isPresent()) {
            LOGGER.info(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "GPG45 profile matched")
                            .with(LOG_VOT.getFieldName(), votToCheck));
            return true;
        }
        return false;
    }
}
