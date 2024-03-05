package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonRootName;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@JsonRootName(value = "routes")
public class MitigationRoute {
    private String event;
    private String document;
}
