package uk.gov.di.ipv.core.processjourneyevent.statemachine.validators;

import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.StepResponseException;

import java.util.Map;
import java.util.Set;

public abstract class AbstractPageContextValidator implements IPageContextValidator {
    abstract Map<String, Set<String>> getAllowedContextsByPage();

    public static final String JOURNEY_TYPE = "journeyType";
    public static final String REASON = "reason";
    public static final String NO_ADDRESS = "noAddress";
    public static final String ALLOW_NINO = "allowNino";
    public static final String INVALID_DOC = "invalidDoc";
    public static final String REMOVE_F2F = "removeF2f";
    public static final String NINO_ONLY = "ninoOnly";
    public static final String IS_UNRECOVERABLE = "isUnrecoverable";
    public static final String SMARTPHONE = "smartphone";
    public static final String IS_APP_ONLY = "isAppOnly";
    public static final String DEVICE_TYPE = "deviceType";
    public static final String IS_EXISTING_IDENTITY_VALID = "isExistingIdentityValid";
    public static final String IS_EXISTING_IDENTITY_INVALID = "isExistingIdentityInvalid";
    public static final String IS_FROM_STRATEGIC_APP = "isFromStrategicApp";
    public static final String PHOTO_ID = "photoId";

    @Override
    public void validate(String pageId, Map<String, Object> pageContext) {
        if (pageContext == null || pageContext.isEmpty()) {
            return;
        }

        var allowedContexts = getAllowedContextsByPage().get(pageId);
        if (allowedContexts == null) {
            throw new StepResponseException(
                    "Page '%s' does not allow any pageContexts. If required, please add to ALLOWED_CONTEXTS_BY_PAGE"
                            .formatted(pageId));
        }

        var contextKeys = pageContext.keySet();
        var disallowedKeys =
                contextKeys.stream().filter(key -> !allowedContexts.contains(key)).findFirst();
        if (disallowedKeys.isPresent()) {
            throw new StepResponseException(
                    "Context '%s' is not allowed for page '%s'. If required, please add to ALLOWED_CONTEXTS_BY_PAGE."
                            .formatted(disallowedKeys.get(), pageId));
        }

        var missingKeys =
                allowedContexts.stream().filter(key -> !contextKeys.contains(key)).findFirst();
        if (missingKeys.isPresent()) {
            throw new StepResponseException(
                    "Required context '%s' is missing for page '%s'."
                            .formatted(missingKeys.get(), pageId));
        }
    }
}
