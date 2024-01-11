package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class ReplayItem {
    Map<String, String> dateCreated;
    Map<String, String> credentialIssuer;
    Map<String, String> userId;
}
