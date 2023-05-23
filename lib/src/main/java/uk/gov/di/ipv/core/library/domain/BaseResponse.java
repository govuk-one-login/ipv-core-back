package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.library.domain.buildclientoauthresponse.ClientResponse;

import static com.fasterxml.jackson.annotation.JsonTypeInfo.As.PROPERTY;
import static com.fasterxml.jackson.annotation.JsonTypeInfo.Id.NAME;

@JsonTypeInfo(use = NAME, include = PROPERTY)
@JsonSubTypes({@JsonSubTypes.Type(value = ClientResponse.class, name = "client")})
public interface BaseResponse {}
