package uk.gov.di.ipv.core.processjourneyevent.statemachine.validators;

import java.util.Map;
import java.util.Set;

public class TestPageContextValidator extends AbstractPageContextValidator {
    private static final Map<String, Set<String>> ALLOWED_CONTEXTS_BY_PAGE =
            Map.ofEntries(
                    Map.entry("page-id-for-page-state", Set.of(REASON)),
                    Map.entry("page-with-missing-context", Set.of(REASON, JOURNEY_TYPE)));

    @Override
    Map<String, Set<String>> getAllowedContextsByPage() {
        return ALLOWED_CONTEXTS_BY_PAGE;
    }
}
