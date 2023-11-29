package uk.gov.di.ipv.core.processcricallback.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;

@Getter
public class ParseCriCallbackRequestException extends JsonProcessingException {
    public ParseCriCallbackRequestException(JsonProcessingException exception) {
        super(exception);
    }
}
