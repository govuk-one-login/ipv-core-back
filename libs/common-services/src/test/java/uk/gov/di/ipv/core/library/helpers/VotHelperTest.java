package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VotHelperTest {
    @Test
    void getVotsByStrengthDescendingOrdersVotsCorrectly() {
        var clientOAuthSessionItem =
                ClientOAuthSessionItem.builder().vtr(List.of("P1", "P2", "PCL250")).build();

        var vots = VotHelper.getVotsByStrengthDescending(clientOAuthSessionItem);

        assertEquals(List.of(Vot.P2, Vot.PCL250, Vot.P1), vots);
    }

    @Test
    void getVotsByStrengthDescendingSkipsUnknownVots() {
        var clientOAuthSessionItem =
                ClientOAuthSessionItem.builder().vtr(List.of("P1", "UNKNOWN", "P2")).build();

        var vots = VotHelper.getVotsByStrengthDescending(clientOAuthSessionItem);

        assertEquals(List.of(Vot.P2, Vot.P1), vots);
    }

    @Test
    void getThresholdVotUsesAchievedIfNotP0() {
        var ipvSessionItem = IpvSessionItem.builder().vot(Vot.P1).build();
        var clientOAuthSessionItem =
                ClientOAuthSessionItem.builder().vtr(List.of("P1", "P2", "PCL250")).build();

        var thresholdVot = VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem);

        assertEquals(Vot.P1, thresholdVot);
    }

    @Test
    void getThresholdVotUsesLowestRequestedIfAchievedP0() {
        var ipvSessionItem = IpvSessionItem.builder().vot(Vot.P0).build();
        var clientOAuthSessionItem =
                ClientOAuthSessionItem.builder().vtr(List.of("P1", "P2", "PCL250")).build();

        var thresholdVot = VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem);

        assertEquals(Vot.P1, thresholdVot);
    }

    @Test
    void getThresholdVotThrowsIfNoRequestedVots() {
        var ipvSessionItem = IpvSessionItem.builder().vot(Vot.P0).build();
        var clientOAuthSessionItem = ClientOAuthSessionItem.builder().vtr(null).build();

        assertThrows(
                IllegalStateException.class,
                () -> VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem));
    }
}
