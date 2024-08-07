package uk.gov.di.ipv.core.reportuseridentity.domain;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.List;
import java.util.Map;

public record TableScanResult<T>(List<T> items, Map<String, AttributeValue> lastEvaluatedKey) {}
