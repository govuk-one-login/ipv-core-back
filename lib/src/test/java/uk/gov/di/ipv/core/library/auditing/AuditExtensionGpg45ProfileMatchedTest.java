package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class AuditExtensionGpg45ProfileMatchedTest {

    private static final ObjectMapper om = new ObjectMapper();
    private static MockedStatic<Clock> clockMock;
    private static MockedStatic<Instant> instantMock;

    @BeforeAll
    public static void setup() {
        var currentInstant = Instant.ofEpochSecond(1666170506);

        clockMock = mockStatic(Clock.class);
        Clock spyClock = spy(Clock.class);
        clockMock.when(Clock::systemUTC).thenReturn(spyClock);
        when(spyClock.instant()).thenReturn(currentInstant);
        instantMock = mockStatic(Instant.class);
        instantMock.when(Instant::now).thenReturn(currentInstant);
    }

    @AfterAll
    public static void tearDown() {
        clockMock.close();
        instantMock.close();
    }

    @Test
    void shouldSerializeToTheCorrectJson() throws Exception {
        AuditExtensionGpg45ProfileMatched extension =
                new AuditExtensionGpg45ProfileMatched(
                        Gpg45Profile.M1A,
                        new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2),
                        List.of("txn1", "txn2", "txn3"));

        AuditEventUser user =
                new AuditEventUser("user-id", "session-id", "journey-id", "ip-address");

        AuditEvent auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_GPG45_PROFILE_MATCHED, "component-id", user, extension);

        String expected =
                "{"
                        + "\"event_name\":\"IPV_GPG45_PROFILE_MATCHED\","
                        + "\"component_id\":\"component-id\","
                        + "\"user\":{"
                        + "\"user_id\":\"user-id\","
                        + "\"session_id\":\"session-id\","
                        + "\"govuk_signin_journey_id\":\"journey-id\","
                        + "\"ip_address\":\"ip-address\""
                        + "},"
                        + "\"extensions\":{"
                        + "\"gpg45Profile\":\"M1A\","
                        + "\"gpg45Scores\":{"
                        + "\"evidences\":[{"
                        + "\"strength\":4,"
                        + "\"validity\":2"
                        + "}],"
                        + "\"activity\":0,"
                        + "\"fraud\":1,"
                        + "\"verification\":2"
                        + "},"
                        + "\"vcTxnIds\":[\"txn1\",\"txn2\",\"txn3\"]"
                        + "},"
                        + "\"timestamp\":1666170506"
                        + "}";

        assertEquals(expected, om.writeValueAsString(auditEvent));
    }
}
