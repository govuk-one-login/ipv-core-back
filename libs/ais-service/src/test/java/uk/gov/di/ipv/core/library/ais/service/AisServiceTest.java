package uk.gov.di.ipv.core.library.ais.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.ais.TestData;
import uk.gov.di.ipv.core.library.ais.client.AisClient;
import uk.gov.di.ipv.core.library.ais.exception.AisClientException;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AisServiceTest {
    private static final String TEST_USER_ID = "testUserId";

    @Mock AisClient aisClient;

    AisService underTest;

    @BeforeEach
    void setUp() {
        underTest = new AisService(aisClient);
    }

    @Test
    void fetchAccountState_whenCalled_returnsState() throws AisClientException {
        // Arrange
        when(aisClient.getAccountInterventionStatus(TEST_USER_ID))
                .thenReturn(TestData.AIS_NO_INTERVENTION_DTO);

        // Act
        var result = underTest.fetchAccountState(TEST_USER_ID);

        // Assert
        assertThat(result).isEqualTo(TestData.AIS_NO_INTERVENTION_DTO.getState());
    }
}
