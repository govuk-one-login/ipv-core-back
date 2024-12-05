package uk.gov.di.ipv.core.library.dynatracesupport;

import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.context.propagation.TextMapPropagator;

public class JourneyRequestPropagators implements ContextPropagators {
    @Override
    public TextMapPropagator getTextMapPropagator() {
        return W3CTraceContextPropagator.getInstance();
    }
}
