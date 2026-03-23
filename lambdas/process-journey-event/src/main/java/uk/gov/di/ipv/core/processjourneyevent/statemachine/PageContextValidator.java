package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import java.util.Map;
import java.util.Set;

public class PageContextValidator implements IPageContextValidator {
    private static final Map<String, Set<String>> ALLOWED_CONTEXTS_BY_PAGE =
            Map.ofEntries(
                    Map.entry("delete-handover", Set.of("journeyType")),
                    Map.entry("no-photo-id-security-questions-find-another-way", Set.of("reason")),
                    Map.entry("page-dcmaw-success", Set.of("noAddress")),
                    Map.entry("page-ipv-pending", Set.of("allowDeleteDetails")),
                    Map.entry("page-ipv-success", Set.of("journeyType")),
                    Map.entry("page-multiple-doc-check", Set.of("allowNino")),
                    Map.entry("page-update-name", Set.of("journeyType")),
                    Map.entry("photo-id-security-questions-find-another-way", Set.of("reason")),
                    Map.entry("prove-identity-another-type-photo-id", Set.of("invalidDoc")),
                    Map.entry("prove-identity-another-way", Set.of("removeF2f")),
                    Map.entry("prove-identity-no-other-photo-id", Set.of("invalidDoc")),
                    Map.entry("prove-identity-no-photo-id", Set.of("ninoOnly")),
                    Map.entry("pyi-details-deleted", Set.of("journeyType")),
                    Map.entry("pyi-no-match", Set.of("reason")),
                    Map.entry("pyi-triage-desktop-download-app", Set.of("smartphone", "isAppOnly")),
                    Map.entry("pyi-triage-mobile-download-app", Set.of("smartphone", "isAppOnly")),
                    Map.entry("pyi-triage-select-smartphone", Set.of("deviceType")),
                    Map.entry("sorry-could-not-confirm-details", Set.of("isExistingIdentityValid")),
                    Map.entry("sorry-technical-problem", Set.of("reason")),
                    Map.entry(
                            "uk-driving-licence-details-not-correct", Set.of("isFromStrategicApp")),
                    Map.entry("update-details-failed", Set.of("isExistingIdentityInvalid")),
                    Map.entry(
                            "update-name-date-birth",
                            Set.of("journeyType", "allowAccountDeletion")));

    @Override
    public Map<String, Set<String>> getAllowedContextsByPage() {
        return ALLOWED_CONTEXTS_BY_PAGE;
    }
}
