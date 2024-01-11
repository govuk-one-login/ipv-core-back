package uk.gov.di.ipv.core.initialiseipvsession.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import static uk.gov.di.ipv.core.library.domain.VocabConstants.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.CORE_IDENTITY_JWT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.INHERITED_IDENTITY_JWT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.PASSPORT_CLAIM_NAME;

@JsonIgnoreProperties(ignoreUnknown = true)
public record JarUserInfo(
        @JsonProperty(value = ADDRESS_CLAIM_NAME) Essential addressClaim,
        @JsonProperty(value = CORE_IDENTITY_JWT_CLAIM_NAME) Essential coreIdentityJwtClaim,
        @JsonProperty(value = INHERITED_IDENTITY_JWT_CLAIM_NAME)
                InheritedIdentityJwtClaim inheritedIdentityClaim,
        @JsonProperty(value = PASSPORT_CLAIM_NAME) Essential passportClaim) {}
