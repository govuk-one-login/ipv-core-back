package uk.gov.di.ipv.core.replaycimitvcs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;

@ExtendWith(MockitoExtension.class)
public class ReplayCimitVcsHandlerTest {
    @InjectMocks private ReplayCimitVcsHandler replayCimitVcsHandler;

    @Test
    void shouldPass() {
        assertFalse(Objects.isNull(replayCimitVcsHandler));
    }
}
