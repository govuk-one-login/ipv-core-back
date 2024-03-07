package uk.gov.di.ipv.coreback.handlers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HomeHandlerTest {
    @Test
    void canServeAPenguin() throws Exception {
        String homePage = (String) HomeHandler.serveHomePage.handle(null, null);
        assertEquals("🐧", homePage);
    }
}
