package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.service.VotMatcher;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.ContraIndicator;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GPG45_PROFILE;

public class EvaluateGpg45ScoresService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final UserIdentityService userIdentityService;
    private final ConfigService configService;
    private final AuditService auditService;
    private final CimitUtilityService cimitUtilityService;
    private final VotMatcher votMatcher;

    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresService(
            ConfigService configService,
            UserIdentityService userIdentityService,
            AuditService auditService,
            CimitUtilityService cimitUtilityService,
            VotMatcher votMatcher) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.auditService = auditService;
        this.cimitUtilityService = cimitUtilityService;
        this.votMatcher = votMatcher;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresService(ConfigService configService, AuditService auditService) {
        this.configService = configService;
        this.userIdentityService = new UserIdentityService(configService);
        this.auditService = auditService;
        this.cimitUtilityService = new CimitUtilityService(configService);
        this.votMatcher = new VotMatcher(userIdentityService, new Gpg45ProfileEvaluator());
        VcHelper.setConfigService(this.configService);
    }

    public Optional<Gpg45Profile> findMatchingGpg45Profile(
            List<VerifiableCredential> vcs,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            List<ContraIndicator> contraIndicators,
            AuditEventUser auditEventUser)
            throws HttpResponseExceptionWithErrorBody, ParseException {
        if (!userIdentityService.checkRequiresAdditionalEvidence(vcs)) {
            var requestedVotsByStrength =
                    clientOAuthSessionItem.getParsedVtr().getRequestedVotsByStrengthDescending();

            var gpg45Vots =
                    requestedVotsByStrength.stream()
                            .filter(vot -> vot.getProfileType() == ProfileType.GPG45)
                            .toList();

            var matchedVot =
                    votMatcher.matchFirstVot(
                            gpg45Vots,
                            vcs,
                            contraIndicators,
                            userIdentityService.areVcsCorrelated(
                                    VcHelper.filterVCBasedOnProfileType(vcs, GPG45)));

            if (matchedVot.isEmpty()) {
                return Optional.empty();
            }

            var isBreaching =
                    contraIndicators != null
                            && cimitUtilityService.isBreachingCiThreshold(
                                    contraIndicators, matchedVot.get().vot());

            if (!isBreaching) {
                LOGGER.info(
                        LogHelper.buildLogMessage("GPG45 profile has been met.")
                                .with(
                                        LOG_GPG45_PROFILE.getFieldName(),
                                        matchedVot.get().gpg45Profile().getLabel()));
                auditService.sendAuditEvent(
                        buildProfileMatchedAuditEvent(
                                matchedVot.get().gpg45Profile(),
                                matchedVot.get().gpg45Scores(),
                                vcs,
                                deviceInformation,
                                auditEventUser));

                return Optional.of(matchedVot.get().gpg45Profile());
            }
        }
        return Optional.empty();
    }

    private AuditEvent buildProfileMatchedAuditEvent(
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<VerifiableCredential> credentials,
            String deviceInformation,
            AuditEventUser auditEventUser) {
        return AuditEvent.createWithDeviceInformation(
                AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                auditEventUser,
                new AuditExtensionGpg45ProfileMatched(
                        gpg45Profile,
                        gpg45Scores,
                        VcHelper.extractTxnIdsFromCredentials(credentials)),
                new AuditRestrictedDeviceInformation(deviceInformation));
    }
}
