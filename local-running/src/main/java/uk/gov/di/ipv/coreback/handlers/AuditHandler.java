package uk.gov.di.ipv.coreback.handlers;

import io.javalin.http.Context;
import uk.gov.di.ipv.core.library.service.LocalAuditService;

public class AuditHandler {
    public void getAuditEvents(Context ctx) {
        ctx.json(LocalAuditService.getAuditEvents(ctx.queryParam("user_id")));
    }
}
