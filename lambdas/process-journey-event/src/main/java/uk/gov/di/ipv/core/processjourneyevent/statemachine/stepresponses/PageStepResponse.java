package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.StepResponseException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageStepResponse implements StepResponse {
    private static final Logger LOGGER = LogManager.getLogger();

    private String pageId;
    private String context;
    private String mitigationStart;

    public Map<String, Object> value() {
        try {
            URIBuilder uriBuilder = new URIBuilder(pageId);
            if (Objects.nonNull(context)) {
                uriBuilder.addParameter("context", context);
            }
            if (Objects.nonNull(mitigationStart)) {
                uriBuilder.addParameter("mitigationStart", mitigationStart);
            }
            URI journeyUri = uriBuilder.build();

            return Map.of("page", journeyUri.toString());
        } catch (URISyntaxException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), e.getMessage())
                            .with("context", context)
                            .with("mitigationStart", mitigationStart));
            throw new StepResponseException(e);
        }
    }
}
