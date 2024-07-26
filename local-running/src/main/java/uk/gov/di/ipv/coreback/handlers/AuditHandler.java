package uk.gov.di.ipv.coreback.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import spark.Request;
import spark.Response;
import spark.Route;
import uk.gov.di.ipv.core.library.service.LocalAuditService;

public class AuditHandler {
    private static final String APPLICATION_JSON = "application/json";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final Route auditEvents =
            (Request request, Response response) -> {
                response.type(APPLICATION_JSON);
                return OBJECT_MAPPER.writeValueAsString(
                        LocalAuditService.getAuditEvents(
                                request.queryParams("govuk_signin_journey_id")));
            };

    public Route getAuditEvents() {
        return auditEvents;
    }
}
