package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(
        value = {"message"},
        allowGetters = true)
public class JourneyErrorResponse extends JourneyResponse {
    @JsonProperty private int statusCode;

    @JsonProperty private ErrorResponse code;

    private String message;

    @JsonCreator
    public JourneyErrorResponse(
            @JsonProperty(value = "journey", required = true) String journey,
            @JsonProperty(value = "statusCode") int statusCode,
            @JsonProperty(value = "code") ErrorResponse code) {
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

    public int getStatusCode() {
        return this.statusCode;
    }

    public int getCode() {
        return this.code != null ? this.code.getCode() : 0;
    }
}
