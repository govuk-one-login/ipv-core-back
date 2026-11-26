package uk.gov.di.ipv.core.storetriagedata.triage;

import uk.gov.di.ipv.core.library.persistence.item.DynamicRoutingState;
import uk.gov.di.ipv.core.storetriagedata.exceptions.InvalidTriageDataException;

import java.util.List;

/**
 * A triage question asked on a single core-front page. Implementations validate the raw answers
 * submitted by core-front and transform them into typed fields on the {@link DynamicRoutingState}.
 */
public interface TriageQuestion {
    /** The core-front page id that this question is asked on. */
    String pageId();

    /**
     * Validate the submitted answers and record them on the state. Must leave the state unchanged
     * if the answers are invalid.
     */
    void apply(List<String> answers, DynamicRoutingState state) throws InvalidTriageDataException;
}
