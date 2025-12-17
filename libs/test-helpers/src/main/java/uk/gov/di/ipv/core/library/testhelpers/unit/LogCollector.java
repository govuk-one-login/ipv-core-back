package uk.gov.di.ipv.core.library.testhelpers.unit;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;

import java.util.ArrayList;
import java.util.List;

@lombok.Getter
public class LogCollector extends AbstractAppender {
    private final List<String> logMessages = new ArrayList<>();

    private LogCollector() {
        super("LogCollector", null, null, true, null);
    }

    @Override
    public void append(LogEvent event) {
        logMessages.add(event.getMessage().getFormattedMessage());
    }

    public static LogCollector getLogCollectorFor(Class<?> clazz) {
        var logCollector = new LogCollector();
        logCollector.start();
        var logger = (Logger) LogManager.getLogger(clazz);
        logger.get().addAppender(logCollector, Level.ALL, null);

        return logCollector;
    }

    public void reset() {
        logMessages.clear();
    }
}
