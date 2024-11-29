package uk.gov.di.ipv.core.library.helpers;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Flow;

public class HttpRequestHelper {
    private HttpRequestHelper() {}

    public static String extractBody(HttpRequest httpRequest) {
        return httpRequest
                .bodyPublisher()
                .map(
                        p -> {
                            var subscriber = new StringSubscriber();
                            p.subscribe(subscriber);
                            return subscriber.getResult();
                        })
                .orElse(null);
    }

    static final class StringSubscriber implements Flow.Subscriber<ByteBuffer> {
        final HttpResponse.BodySubscriber<String> bodySubscriber;

        StringSubscriber() {
            this.bodySubscriber = HttpResponse.BodySubscribers.ofString(StandardCharsets.UTF_8);
        }

        public String getResult() {
            return bodySubscriber.getBody().toCompletableFuture().join();
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            bodySubscriber.onSubscribe(subscription);
        }

        @Override
        public void onNext(ByteBuffer item) {
            bodySubscriber.onNext(List.of(item));
        }

        @Override
        public void onError(Throwable throwable) {
            bodySubscriber.onError(throwable);
        }

        @Override
        public void onComplete() {
            bodySubscriber.onComplete();
        }
    }
}
