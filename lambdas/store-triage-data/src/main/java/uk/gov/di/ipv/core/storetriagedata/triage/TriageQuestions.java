package uk.gov.di.ipv.core.storetriagedata.triage;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/** The set of triage questions that core-front is allowed to submit answers for. */
public class TriageQuestions {
    private final Map<String, TriageQuestion> questionsByPageId;

    public TriageQuestions(List<TriageQuestion> questions) {
        this.questionsByPageId =
                questions.stream()
                        .collect(
                                Collectors.toUnmodifiableMap(
                                        TriageQuestion::pageId, Function.identity()));
    }

    /** The questions currently supported. Add new triage questions here. */
    public static TriageQuestions createDefault() {
        return new TriageQuestions(List.of(new LiveInUkQuestion()));
    }

    public Optional<TriageQuestion> find(String pageId) {
        return Optional.ofNullable(questionsByPageId.get(pageId));
    }
}
