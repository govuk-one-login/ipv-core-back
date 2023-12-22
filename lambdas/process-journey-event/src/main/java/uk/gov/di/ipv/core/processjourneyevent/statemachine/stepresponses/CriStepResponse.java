package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.StepResponseException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CONTEXT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SCOPE;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CriStepResponse implements StepResponse {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String CRI_JOURNEY_TEMPLATE = "/journey/cri/build-oauth-request/%s";
    private String criId;
    private String context;
    private String scope;
    @Getter private Boolean mitigationStart;

    public Map<String, Object> value() {
        try {
            URIBuilder uriBuilder = new URIBuilder(String.format(CRI_JOURNEY_TEMPLATE, criId));
            if (Objects.nonNull(context)) {
                uriBuilder.addParameter("context", context);
            }
            if (Objects.nonNull(scope)) {
                uriBuilder.addParameter("scope", scope);
            }
            URI journeyUri = uriBuilder.build();

            return Map.of("journey", journeyUri.toString());
        } catch (URISyntaxException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), e.getMessage())
                            .with(LOG_CRI_ID.getFieldName(), criId)
                            .with(LOG_CONTEXT.getFieldName(), context)
                            .with(LOG_SCOPE.getFieldName(), scope));
            throw new StepResponseException(e);
        }
    }
}
