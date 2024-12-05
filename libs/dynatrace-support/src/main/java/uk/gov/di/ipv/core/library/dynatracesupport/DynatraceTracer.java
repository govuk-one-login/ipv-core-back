package uk.gov.di.ipv.core.library.dynatracesupport;

// import com.dynatrace.oneagent.sdk.OneAgentSDKFactory;
// import com.dynatrace.oneagent.sdk.api.IncomingWebRequestTracer;
// import com.dynatrace.oneagent.sdk.api.OneAgentSDK;
// import com.dynatrace.oneagent.sdk.api.infos.WebApplicationInfo;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanBuilder;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.ContextKey;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.Optional;

public class DynatraceTracer {
    private static final Logger LOGGER = LogManager.getLogger();
    //    private OneAgentSDK oneAgentSDK;
    //    private WebApplicationInfo webApplicationInfo;
    //
    //    private IncomingWebRequestTracer tracer;
    private Span otSpan;

    public DynatraceTracer() {}

    public DynatraceTracer(String env, String lambdaName) {
        OpenTelemetry openTelemetry = GlobalOpenTelemetry.get();
        LOGGER.info(
                LogHelper.buildLogMessage("Global OT from init")
                        .with("global OT", GlobalOpenTelemetry.class)
                        .with("open telemetry", openTelemetry)
                        .with("propagators", openTelemetry.getPropagators())
                        .with("tracerProvider", openTelemetry.getTracerProvider()));

        OpenTelemetrySdk build =
                OpenTelemetrySdk.builder().setPropagators(new JourneyRequestPropagators()).build();
        LOGGER.info(LogHelper.buildLogMessage("Built OT").with("ot", build));

        GlobalOpenTelemetry.set(build);

        OpenTelemetry openTelemetryAfterSet = GlobalOpenTelemetry.get();
        LOGGER.info(
                LogHelper.buildLogMessage("Global OT after set")
                        .with("global OT", GlobalOpenTelemetry.class.getCanonicalName())
                        .with("open telemetry", openTelemetryAfterSet)
                        .with("propagators", openTelemetryAfterSet.getPropagators())
                        .with("tracerProvider", openTelemetryAfterSet.getTracerProvider()));
        //        this.oneAgentSDK = initOneAgentSdk();
        //        this.webApplicationInfo =
        //                oneAgentSDK.createWebApplicationInfo(
        //                        String.format("core-back-%s", env),
        //                        String.format("%s-%s-test", lambdaName, env),
        //                        "/");
    }

    public void start(JourneyRequest journeyRequest) {
        LOGGER.info(
                LogHelper.buildLogMessage("Journey request")
                        .with(
                                "traceparent",
                                Optional.ofNullable(journeyRequest.getTraceParent())
                                        .orElse("not found"))
                        .with(
                                "tracestate",
                                Optional.ofNullable(journeyRequest.getTraceState())
                                        .orElse("not found")));

        Context rootContext = Context.root();
        LOGGER.info(
                LogHelper.buildLogMessage("Extracted context")
                        .with(
                                "traceparent",
                                Optional.ofNullable(
                                                rootContext.get(ContextKey.named("traceparent")))
                                        .orElse("not found"))
                        .with(
                                "tracestate",
                                Optional.ofNullable(rootContext.get(ContextKey.named("tracestate")))
                                        .orElse("not found")));

        Tracer otTracer = GlobalOpenTelemetry.getTracer("instrumentation-library-name", "1.0.0");
        LOGGER.info(LogHelper.buildLogMessage(otTracer.toString()));
        LOGGER.info(LogHelper.buildLogMessage(otTracer.getClass().getTypeName()));
        LOGGER.info(LogHelper.buildLogMessage(otTracer.getClass().getCanonicalName()));

        Context extractedContext =
                W3CTraceContextPropagator.getInstance()
                        .extract(Context.current(), journeyRequest, new JourneyRequestGetter());

        //        LOGGER.info(LogHelper.buildLogMessage("Extracted context")
        //                .with("traceparent",
        // extractedContext.get(ContextKey.named("traceparent")))
        //                .with("tracestate",
        // extractedContext.get(ContextKey.named("tracestate"))));

        var parentSpan = Span.fromContext(extractedContext);
        SpanContext parentSpanContext = parentSpan.getSpanContext();
        boolean valid = parentSpanContext.isValid();
        String traceId = parentSpanContext.getTraceId();

        LOGGER.info(LogHelper.buildLogMessage(String.format("valid: %s", valid)));
        LOGGER.info(LogHelper.buildLogMessage(String.format("traceId: %s", traceId)));

        SpanBuilder thingy = otTracer.spanBuilder("thingy");
        LOGGER.info(LogHelper.buildLogMessage(thingy.toString()));
        LOGGER.info(LogHelper.buildLogMessage(thingy.getClass().getTypeName()));
        LOGGER.info(LogHelper.buildLogMessage(thingy.getClass().getCanonicalName()));
        otSpan = thingy.setSpanKind(SpanKind.SERVER).setParent(extractedContext).startSpan();

        LOGGER.info(
                LogHelper.buildLogMessage("otSpan")
                        .with("traceId", otSpan.getSpanContext().getTraceId())
                        .with("spanId", otSpan.getSpanContext().getSpanId())
                        .with("spanId", otSpan.getSpanContext().getTraceState()));

        //        otSpan.makeCurrent();

        //        tracer =
        //                oneAgentSDK.traceIncomingWebRequest(
        //                        webApplicationInfo, journeyRequest.getJourney(), POST.name());
        //        tracer.addRequestHeader("traceparent", journeyRequest.getTraceParent());
        //        tracer.addRequestHeader("tracestate", journeyRequest.getTraceState());
        //        tracer.addRequestHeader("x-dynatrace", journeyRequest.getDynatrace());
        //        tracer.start();

        LOGGER.info(
                LogHelper.buildLogMessage("Started dynatrace incoming web request tracer")
                        .with("traceparent", journeyRequest.getTraceParent())
                        .with("tracestate", journeyRequest.getTraceState())
                        .with("x-dynatrace", journeyRequest.getDynatrace()));

        //        var traceContextInfo = oneAgentSDK.getTraceContextInfo();
        //        LOGGER.info(LogHelper.buildLogMessage("Trace context from PurePath node")
        //                .with("traceId", traceContextInfo.getTraceId())
        //                .with("spanId", traceContextInfo.getSpanId()));

    }

    public void setStatusCode(int statusCode) {
        //        tracer.setStatusCode(statusCode);
    }

    public void error(int statusCode, Throwable e) {
        otSpan.recordException(e);
        //        tracer.setStatusCode(statusCode);
        //        tracer.error(e);
    }

    public void end() {
        otSpan.end();
        //        tracer.end();
    }

    //    private OneAgentSDK initOneAgentSdk() {
    //        var oneAgentSdk = OneAgentSDKFactory.createInstance();
    //        oneAgentSdk.setLoggingCallback(new TracerLoggingCallback());
    //        switch (oneAgentSdk.getCurrentState()) {
    //            case ACTIVE:
    //                LOGGER.info(LogHelper.buildLogMessage("Dynatrace SDK is active and
    // capturing"));
    //                break;
    //            case PERMANENTLY_INACTIVE:
    //                LOGGER.error(LogHelper.buildLogMessage("SDK is PERMANENT_INACTIVE; Probably no
    // OneAgent injected or OneAgent is incompatible with SDK"));
    //                break;
    //            case TEMPORARILY_INACTIVE:
    //                LOGGER.error(LogHelper.buildLogMessage("SDK is TEMPORARY_INACTIVE; OneAgent
    // has been deactivated - check OneAgent configuration"));
    //                break;
    //            default:
    //                LOGGER.error(LogHelper.buildLogMessage("SDK is in unknown
    // state").with("state", oneAgentSdk.getCurrentState()));
    //                break;
    //        }
    //
    //        return oneAgentSdk;
    //    }
}
