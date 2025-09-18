package uk.gov.di.ipv.core.library.annotations;

import com.fasterxml.jackson.annotation.JacksonAnnotationsInside;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import uk.gov.di.ipv.core.library.helpers.RemoveEscapedQuotesDeserializer;

import java.lang.annotation.*;

// This is because in the config we still have escapes in the keys
// which used to need to be escaped for when the parent CRI configs used to be JSON strings
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@JacksonAnnotationsInside
@JsonDeserialize(using = RemoveEscapedQuotesDeserializer.class)
public @interface RemoveEscapedQuotationMarks {}
