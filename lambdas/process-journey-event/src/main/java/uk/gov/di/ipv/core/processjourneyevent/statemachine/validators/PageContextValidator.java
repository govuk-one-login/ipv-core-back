package uk.gov.di.ipv.core.processjourneyevent.statemachine.validators;

import java.util.Map;
import java.util.Set;

public class PageContextValidator extends AbstractPageContextValidator {

    private static final Map<String, Set<String>> ALLOWED_CONTEXTS_BY_PAGE =
            Map.ofEntries(
                    Map.entry("delete-handover", Set.of(JOURNEY_TYPE)),
                    Map.entry("need-more-information-confirm-change-details", Set.of(JOURNEY_TYPE)),
                    Map.entry("no-photo-id-web-find-another-way", Set.of(REASON)),
                    Map.entry("page-dcmaw-success", Set.of(NO_ADDRESS)),
                    Map.entry("page-ipv-success", Set.of(JOURNEY_TYPE)),
                    Map.entry("page-multiple-doc-check", Set.of(ALLOW_NINO)),
                    Map.entry("page-update-name", Set.of(JOURNEY_TYPE)),
                    Map.entry("photo-id-web-find-another-way", Set.of(REASON)),
                    Map.entry("prove-identity-another-type-photo-id", Set.of(INVALID_DOC)),
                    Map.entry("prove-identity-another-way", Set.of(REMOVE_F2F)),
                    Map.entry("prove-identity-no-other-photo-id", Set.of(INVALID_DOC)),
                    Map.entry("prove-identity-no-photo-id", Set.of(NINO_ONLY)),
                    Map.entry("prove-identity-online", Set.of(PHOTO_ID)),
                    Map.entry("prove-identity-online-banking", Set.of(PHOTO_ID)),
                    Map.entry("pyi-no-match", Set.of(REASON)),
                    Map.entry("pyi-technical", Set.of(IS_UNRECOVERABLE)),
                    Map.entry("pyi-triage-desktop-download-app", Set.of(SMARTPHONE, IS_APP_ONLY)),
                    Map.entry("pyi-triage-mobile-download-app", Set.of(SMARTPHONE, IS_APP_ONLY)),
                    Map.entry("pyi-triage-select-smartphone", Set.of(DEVICE_TYPE)),
                    Map.entry(
                            "sorry-could-not-confirm-details", Set.of(IS_EXISTING_IDENTITY_VALID)),
                    Map.entry("sorry-technical-problem", Set.of(REASON)),
                    Map.entry(
                            "uk-driving-licence-details-not-correct",
                            Set.of(IS_FROM_STRATEGIC_APP)),
                    Map.entry("update-details-failed", Set.of(IS_EXISTING_IDENTITY_INVALID)),
                    Map.entry("update-name-date-birth", Set.of(JOURNEY_TYPE)));

    @Override
    Map<String, Set<String>> getAllowedContextsByPage() {
        return ALLOWED_CONTEXTS_BY_PAGE;
    }
}
