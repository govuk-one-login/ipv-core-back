package uk.gov.di.ipv.core.processcandidateidentity.domain;

import uk.gov.di.ipv.core.library.auditing.AuditEventUser;

public record SharedAuditEventParameters(AuditEventUser auditEventUser, String deviceInformation) {}
