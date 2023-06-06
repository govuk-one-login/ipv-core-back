package uk.gov.di.ipv.core.library.verifiablecredential.domain;

import lombok.Getter;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Getter
public enum VerifiableCredentialStatus {
    CREATED("created"),
    PENDING("pending");
    private static final Map<String, VerifiableCredentialStatus> STATUSES =
            Arrays.stream(VerifiableCredentialStatus.values())
                    .collect(
                            (Collectors.toMap(
                                    VerifiableCredentialStatus::getStatus, Function.identity())));
    private final String status;

    VerifiableCredentialStatus(String status) {
        this.status = status;
    }

    public static VerifiableCredentialStatus fromStatusString(String status) {
        return STATUSES.get(status);
    }
}
