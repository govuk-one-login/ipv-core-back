package uk.gov.di.ipv.core.reportuseridentity.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ReportProcessingRequest(
        boolean continueUniqueUserScan,
        boolean continueUserIdentityScan,
        Map<String, AttributeValue> tacticalStoreLastEvaluatedKey,
        Map<String, AttributeValue> userIdentitylastEvaluatedKey) {}
