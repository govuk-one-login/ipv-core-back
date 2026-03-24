package uk.gov.di.ipv.core.processjourneyevent.statemachine.validators;

import java.util.Map;
import java.util.Set;

public class TestPageContextValidator extends AbstractPageContextValidator {
    private static final Map<String, Set<String>> ALLOWED_CONTEXTS_BY_PAGE =
            Map.ofEntries(
                    Map.entry("page-id-for-page-state", Set.of("reason")),
                    Map.entry("page-with-missing-context", Set.of("reason", "journeyType")));

    @Override
    Map<String, Set<String>> getAllowedContextsByPage() {
        return ALLOWED_CONTEXTS_BY_PAGE;
    }
}
