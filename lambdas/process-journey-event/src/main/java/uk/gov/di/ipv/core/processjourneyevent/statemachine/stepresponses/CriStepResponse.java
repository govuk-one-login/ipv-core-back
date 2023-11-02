package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.http.client.utils.URIBuilder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Objects;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CriStepResponse implements StepResponse {

    public static final String CRI_JOURNEY_TEMPLATE = "/journey/cri/build-oauth-request/%s";

    private String criId;

    private String context;

    private String scope;

    public Map<String, Object> value() throws URISyntaxException {
        URIBuilder uriBuilder = new URIBuilder(String.format(CRI_JOURNEY_TEMPLATE, criId));
        if (Objects.nonNull(context)) {
            uriBuilder.addParameter("context", context);
        }
        if (Objects.nonNull(scope)) {
            uriBuilder.addParameter("scope", scope);
        }
        URI journeyUri = uriBuilder.build();

        return Map.of("journey", journeyUri.toString());
    }
}
