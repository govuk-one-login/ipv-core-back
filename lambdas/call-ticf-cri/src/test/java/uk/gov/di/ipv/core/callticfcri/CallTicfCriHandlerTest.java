package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;

import static org.junit.jupiter.api.Assertions.assertNull;

@ExtendWith(MockitoExtension.class)
class CallTicfCriHandlerTest {

    @Mock Context mockContext;

    @Test
    void handlerReturnsNull() {
        assertNull(new CallTicfCriHandler().handleRequest(new JourneyRequest(), mockContext));
    }
}
