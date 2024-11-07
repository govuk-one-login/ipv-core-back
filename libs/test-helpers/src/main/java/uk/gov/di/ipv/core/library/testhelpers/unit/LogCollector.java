package uk.gov.di.ipv.core.library.testhelpers.unit;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.message.Message;

import java.util.ArrayList;
import java.util.List;

public class LogCollector extends AbstractAppender {
    List<Message> logMessages = new ArrayList<>();

    private LogCollector() {
        super("LogCollector", null, null, true, null);
    }

    @Override
    public void append(LogEvent event) {
        logMessages.add(event.getMessage());
    }

    public List<Message> getLogMessages() {
        return logMessages;
    }

    public static LogCollector GetLogCollectorFor(Class<?> clazz) {
        var logCollector = new LogCollector();
        var logger = (org.apache.logging.log4j.core.Logger) LogManager.getLogger(clazz);
        logger.get().addAppender(logCollector, Level.ALL, null);

        return logCollector;
    }
}
