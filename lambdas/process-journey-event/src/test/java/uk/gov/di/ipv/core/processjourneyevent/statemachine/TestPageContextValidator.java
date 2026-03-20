package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import java.util.Map;
import java.util.Set;

public class TestPageContextValidator implements IPageContextValidator {
    private static final Map<String, Set<String>> ALLOWED_CONTEXTS_BY_PAGE =
            Map.ofEntries(Map.entry("page-id-for-page-state", Set.of("reason")));

    @Override
    public Map<String, Set<String>> getAllowedContextsByPage() {
        return ALLOWED_CONTEXTS_BY_PAGE;
    }
}
