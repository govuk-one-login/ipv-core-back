package uk.gov.di.ipv.core.storetriagedata.triage;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.persistence.item.DynamicRoutingState;
import uk.gov.di.ipv.core.storetriagedata.exceptions.InvalidTriageDataException;

import java.util.List;

/** The "do you live in the UK" page. A single choice that becomes {@code livesInUk}. */
public class LiveInUkQuestion implements TriageQuestion {
    public static final String PAGE_ID = "live-in-uk";
    static final String UK = "uk";
    static final String INTERNATIONAL = "international";

    @Override
    public String pageId() {
        return PAGE_ID;
    }

    @Override
    public void apply(List<String> answers, DynamicRoutingState state)
            throws InvalidTriageDataException {
        if (answers == null || answers.size() != 1) {
            throw new InvalidTriageDataException(
                    ErrorResponse.INVALID_TRIAGE_ANSWER, "Expected exactly one answer");
        }

        state.setLivesInUk(
                switch (answers.get(0)) {
                    case UK -> true;
                    case INTERNATIONAL -> false;
                    default ->
                            throw new InvalidTriageDataException(
                                    ErrorResponse.INVALID_TRIAGE_ANSWER,
                                    "Unrecognised answer for " + PAGE_ID);
                });
    }
}
