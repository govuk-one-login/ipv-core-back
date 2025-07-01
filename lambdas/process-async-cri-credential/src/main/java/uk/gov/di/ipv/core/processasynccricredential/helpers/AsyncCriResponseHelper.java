package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.core.processasynccricredential.domain.BaseAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.ErrorAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessageDto;

public class AsyncCriResponseHelper {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AsyncCriResponseHelper() {}

    public static BaseAsyncCriResponse getAsyncResponseMessage(String criResponseMessage)
            throws JsonProcessingException {
        final CriResponseMessageDto criResponseMessageDto =
                MAPPER.readerFor(CriResponseMessageDto.class).readValue(criResponseMessage);

        if (criResponseMessageDto.getError() == null) {
            return SuccessAsyncCriResponse.builder()
                    .userId(criResponseMessageDto.getUserId())
                    .oauthState(criResponseMessageDto.getOauthState())
                    .verifiableCredentialJWTs(criResponseMessageDto.getVerifiableCredentialJWTs())
                    .journeyId(criResponseMessageDto.getJourneyId())
                    .build();
        } else {
            return ErrorAsyncCriResponse.builder()
                    .userId(criResponseMessageDto.getUserId())
                    .oauthState(criResponseMessageDto.getOauthState())
                    .error(criResponseMessageDto.getError())
                    .errorDescription(criResponseMessageDto.getErrorDescription())
                    .journeyId(criResponseMessageDto.getJourneyId())
                    .build();
        }
    }

    public static boolean isSuccessAsyncCriResponse(BaseAsyncCriResponse baseAsyncCriResponse) {
        return baseAsyncCriResponse instanceof SuccessAsyncCriResponse;
    }
}
