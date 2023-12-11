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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProcessStepResponse implements StepResponse {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final String JOURNEY = "journey";
    private static final String LAMBDA_INPUT = "lambdaInput";
    private static final String JOURNEY_TEMPLATE = "/journey/%s";
    private String lambda;
    private Map<String, Object> lambdaInput;
    private String mitigationStart;

    @Override
    public Map<String, Object> value() {
        try {
            HashMap<String, Object> response = new HashMap<>();
            URIBuilder uriBuilder = new URIBuilder(String.format(JOURNEY_TEMPLATE, lambda));

            if (Objects.nonNull(mitigationStart)) {
                uriBuilder.addParameter("mitigationStart", mitigationStart);
            }
            URI journeyUri = uriBuilder.build();

            response.put(JOURNEY, journeyUri.toString());
            response.put(LAMBDA_INPUT, lambdaInput);

            return response;
        } catch (URISyntaxException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), e.getMessage())
                            .with("lambda", lambda)
                            .with("mitigationStart", mitigationStart));
            throw new StepResponseException(e);
        }
    }
}
