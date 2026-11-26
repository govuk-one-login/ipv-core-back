package uk.gov.di.ipv.core.storetriagedata.domain;

import java.util.List;

/**
 * Body sent by core-front. {@code answers} is a list so that both single-choice and checkbox
 * questions share one shape.
 */
public record StoreTriageDataRequest(String pageId, List<String> answers) {}
