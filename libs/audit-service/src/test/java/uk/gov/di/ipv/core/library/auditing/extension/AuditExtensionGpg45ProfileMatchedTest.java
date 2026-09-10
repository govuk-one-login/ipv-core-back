package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

class AuditExtensionGpg45ProfileMatchedTest {

    private static final ObjectMapper om = new ObjectMapper();
    private static MockedStatic<Instant> instantMock;
    private static final Instant FIXED_INSTANT = Instant.ofEpochMilli(1666170506321L);

    @BeforeAll
    public static void setup() {
        instantMock = mockStatic(Instant.class, CALLS_REAL_METHODS);
        instantMock.when(Instant::now).thenReturn(FIXED_INSTANT);
    }

    @AfterAll
    public static void tearDown() {
        instantMock.close();
    }

    @Test
    void shouldSerializeToTheCorrectJson() throws Exception {
        AuditExtensionGpg45ProfileMatched extension =
                new AuditExtensionGpg45ProfileMatched(
                        M1A,
                        new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2),
                        List.of("txn1", "txn2", "txn3"));

        AuditEventUser user =
                new AuditEventUser("user-id", "session-id", "journey-id", "ip-address");

        AuditEvent auditEvent =
                AuditEvent.createWithoutDeviceInformation(
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
                        + ","
                        + "\"event_timestamp_ms\":1666170506321"
                        + "}";

        assertEquals(expected, om.writeValueAsString(auditEvent));
    }
}
