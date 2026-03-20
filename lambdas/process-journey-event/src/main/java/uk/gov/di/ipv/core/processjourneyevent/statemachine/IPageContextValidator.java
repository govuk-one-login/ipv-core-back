package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.StepResponseException;

import java.util.Map;
import java.util.Set;

public interface IPageContextValidator {
    Map<String, Set<String>> getAllowedContextsByPage();

    default void validate(String pageId, Map<String, Object> pageContext) {
        if (pageContext == null || pageContext.isEmpty()) {
            return;
        }

        var allowedContexts = getAllowedContextsByPage().get(pageId);
        if (allowedContexts == null) {
            throw new StepResponseException(
                    "Page '%s' does not allow any pageContexts. If required, please add to ALLOWED_CONTEXTS_BY_PAGE"
                            .formatted(pageId));
        }

        for (var key : pageContext.keySet()) {
            if (!allowedContexts.contains(key)) {
                throw new StepResponseException(
                        "Context '%s' is not allowed for page '%s'. If required, please add to ALLOWED_CONTEXTS_BY_PAGE."
                                .formatted(key, pageId));
            }
        }
    }
}
