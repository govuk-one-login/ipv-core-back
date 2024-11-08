package uk.gov.di.ipv.core.library.testhelpers.unit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.StringContains.containsString;

class LogCollectorTest {
    private static final Logger LOGGER = LogManager.getLogger();

    @Test
    void shouldCatchMultipleLogsForInspection() {
        // Arrange
        var underTest = LogCollector.getLogCollectorFor(LogCollectorTest.class);

        // Act
        LOGGER.error("test log 1");
        LOGGER.error("test log 2");

        // Assert
        var collectedMessages = underTest.getLogMessages();
        assertThat(collectedMessages.size(), is(2));
        assertThat(collectedMessages.get(0), containsString("test log 1"));
        assertThat(collectedMessages.get(1), containsString("test log 2"));
    }
}
