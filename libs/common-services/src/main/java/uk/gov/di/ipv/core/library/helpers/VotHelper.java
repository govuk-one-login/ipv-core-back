package uk.gov.di.ipv.core.library.helpers;

import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

public class VotHelper {
    private VotHelper() {}

    /**
     * Gets the VOT to be used as the minimum threshold for passing checks. This will either be the
     * VOT of the identity that has been achieved, or the minimum requested by the client.
     */
    public static Vot getThresholdVot(
            IpvSessionItem ipvSessionItem, ClientOAuthSessionItem clientOAuthSessionItem) {
        if (ipvSessionItem.getVot() != Vot.P0) {
            // If we've met a VOT already, that is the threshold we should use
            return ipvSessionItem.getVot();
        }

        var vtrVots = clientOAuthSessionItem.getVtrAsVots();

        if (vtrVots.isEmpty()) {
            // This may happen on (e.g.) a reverification request
            throw new IllegalStateException("Attempted to calculate threshold VOT with no VTR");
        }

        var gpg45Vots =
                Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH.stream()
                        .filter(vtrVots::contains)
                        .toList();

        return gpg45Vots.get(gpg45Vots.size() - 1);
    }
}
