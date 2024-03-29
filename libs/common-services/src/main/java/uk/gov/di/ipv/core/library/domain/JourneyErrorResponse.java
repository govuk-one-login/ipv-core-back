package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@EqualsAndHashCode(callSuper = true)
@ToString
@JsonIgnoreProperties(
        value = {"message"},
        allowGetters = true)
public class JourneyErrorResponse extends JourneyResponse {
    private final int statusCode;
    private final ErrorResponse code;
    private final String message;

    @JsonCreator
    public JourneyErrorResponse(
            @JsonProperty(value = "journey", required = true) String journey,
            @JsonProperty(value = "statusCode") int statusCode,
            @JsonProperty(value = "code") int code) {
        this(journey, statusCode, ErrorResponse.forCode(code));
    }

    public JourneyErrorResponse(String journey, int statusCode, ErrorResponse code) {
        this(journey, statusCode, code, null);
    }

    public JourneyErrorResponse(
            String journey, int statusCode, ErrorResponse code, String message) {
        super(journey);
        this.statusCode = statusCode;
        this.code = code;
        this.message = message;
    }

    @JsonProperty("message")
    public String getMessage() {
        if (this.message != null) {
            return this.message;
        }
        if (this.code != null) {
            return this.code.getMessage();
        }
        return null;
    }

    @JsonProperty("statusCode")
    public int getStatusCode() {
        return this.statusCode;
    }

    @JsonProperty("code")
    public int getCode() {
        return this.code != null ? this.code.getCode() : 0;
    }
}
