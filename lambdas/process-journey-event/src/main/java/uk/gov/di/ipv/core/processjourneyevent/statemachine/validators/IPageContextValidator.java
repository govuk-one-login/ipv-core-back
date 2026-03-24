package uk.gov.di.ipv.core.processjourneyevent.statemachine.validators;

import java.util.Map;

public interface IPageContextValidator {
    void validate(String pageId, Map<String, Object> pageContext);
}
