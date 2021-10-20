package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class AuthorizationHandlerTest {

    private final Context context = mock(Context.class);

    private AuthorizationHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new AuthorizationHandler();
    }

    @Test
    public void shouldRespondWithKnownValue(){
        String result = handler.handleRequest("Some input", context);
        assertEquals("Hello, this is the stub AuthorizationHandler", result);
    }

}
