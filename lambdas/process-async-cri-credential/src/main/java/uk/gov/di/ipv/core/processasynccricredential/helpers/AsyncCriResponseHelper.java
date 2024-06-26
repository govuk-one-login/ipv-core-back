package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.processasynccricredential.domain.BaseAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.ErrorAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessageDto;

import static uk.gov.di.ipv.core.library.domain.Cri.F2F;

public class AsyncCriResponseHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String DEFAULT_CREDENTIAL_ISSUER = F2F.getId();

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AsyncCriResponseHelper() {}

    public static BaseAsyncCriResponse getAsyncResponseMessage(String criResponseMessage)
            throws JsonProcessingException {
        final CriResponseMessageDto criResponseMessageDto =
                MAPPER.readerFor(CriResponseMessageDto.class).readValue(criResponseMessage);
        if (criResponseMessageDto.getCredentialIssuer() == null) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "Credential Issuer not set, defaulting to "
                                    + DEFAULT_CREDENTIAL_ISSUER));
            criResponseMessageDto.setCredentialIssuer(DEFAULT_CREDENTIAL_ISSUER);
        }
        if (criResponseMessageDto.getError() == null) {
            return SuccessAsyncCriResponse.builder()
                    .credentialIssuer(criResponseMessageDto.getCredentialIssuer())
                    .userId(criResponseMessageDto.getUserId())
                    .oauthState(criResponseMessageDto.getOauthState())
                    .verifiableCredentialJWTs(criResponseMessageDto.getVerifiableCredentialJWTs())
                    .build();
        } else {
            return ErrorAsyncCriResponse.builder()
                    .credentialIssuer(criResponseMessageDto.getCredentialIssuer())
                    .userId(criResponseMessageDto.getUserId())
                    .oauthState(criResponseMessageDto.getOauthState())
                    .error(criResponseMessageDto.getError())
                    .errorDescription(criResponseMessageDto.getErrorDescription())
                    .build();
        }
    }

    public static boolean isSuccessAsyncCriResponse(BaseAsyncCriResponse baseAsyncCriResponse) {
        return baseAsyncCriResponse instanceof SuccessAsyncCriResponse;
    }
}
