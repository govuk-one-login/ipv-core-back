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
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GPG45_PROFILE;

public class EvaluateGpg45ScoresService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final UserIdentityService userIdentityService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final ConfigService configService;
    private final AuditService auditService;
    private final CimitUtilityService cimitUtilityService;

    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresService(
            ConfigService configService,
            UserIdentityService userIdentityService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            AuditService auditService,
            CimitUtilityService cimitUtilityService) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.auditService = auditService;
        this.cimitUtilityService = cimitUtilityService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresService() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresService(ConfigService configService) {
        this.configService = configService;
        this.userIdentityService = new UserIdentityService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.auditService = AuditService.create(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        VcHelper.setConfigService(this.configService);
    }

    public Optional<Gpg45Profile> findMatchingGpg45Profile(
            List<VerifiableCredential> vcs,
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String ipAddress,
            String deviceInformation,
            List<ContraIndicator> contraIndicators) {
        if (!userIdentityService.checkRequiresAdditionalEvidence(vcs)) {
            var gpg45Scores = gpg45ProfileEvaluator.buildScore(vcs);

            var requestedVotsByStrength =
                    clientOAuthSessionItem.getParsedVtr().getRequestedVotsByStrengthDescending();

            var gpg45Vots =
                    requestedVotsByStrength.stream()
                            .filter(vot -> vot.getSupportedGpg45Profiles() != null)
                            .toList();

            for (Vot requestedVot : gpg45Vots) {
                var profiles = requestedVot.getSupportedGpg45Profiles();

                var matchedProfile =
                        gpg45ProfileEvaluator.getFirstMatchingProfile(gpg45Scores, profiles);

                var isBreaching =
                        contraIndicators != null
                                && cimitUtilityService.isBreachingCiThreshold(
                                        contraIndicators, requestedVot);

                if (matchedProfile.isPresent() && !isBreaching) {
                    LOGGER.info(
                            LogHelper.buildLogMessage("GPG45 profile has been met.")
                                    .with(
                                            LOG_GPG45_PROFILE.getFieldName(),
                                            matchedProfile.get().getLabel()));
                    auditService.sendAuditEvent(
                            buildProfileMatchedAuditEvent(
                                    ipvSessionItem,
                                    clientOAuthSessionItem,
                                    matchedProfile.get(),
                                    gpg45Scores,
                                    vcs,
                                    ipAddress,
                                    deviceInformation));

                    return matchedProfile;
                }
            }
        }
        return Optional.empty();
    }

    private AuditEvent buildProfileMatchedAuditEvent(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<VerifiableCredential> credentials,
            String ipAddress,
            String deviceInformation) {
        AuditEventUser auditEventUser =
                new AuditEventUser(
                        clientOAuthSessionItem.getUserId(),
                        ipvSessionItem.getIpvSessionId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        ipAddress);
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
