package uk.gov.di.ipv.core.credentialissuerconfig;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CredentialIssuerConfigHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        List<Map<String, String>> criList = new ArrayList<>();

        Map<String, String> passportStubCri = new HashMap<>();
        passportStubCri.put("id", "PassportIssuer");
        passportStubCri.put("name", "Passport (Stub)");
        passportStubCri.put(
                "authorizeUrl",
                "https://di-ipv-credential-issuer-stub.london.cloudapps.digital/authorize");
        passportStubCri.put(
                "tokenUrl", "https://di-ipv-credential-issuer-stub.london.cloudapps.digital/token");
        passportStubCri.put(
                "credentialUrl",
                "https://di-ipv-credential-issuer-stub.london.cloudapps.digital/credential");
        passportStubCri.put("ipvClientId", "IPV-Core");
        criList.add(passportStubCri);

        Map<String, String> passportDcsCri = new HashMap<>();
        passportStubCri.put("id", "DcsPassportIssuer");
        passportStubCri.put("name", "DCS Passport CRI");
        passportStubCri.put(
                "authorizeUrl",
                "https://di-ipv-cri-uk-passport-front.london.cloudapps.digital/oauth2/authorize");
        passportStubCri.put(
                "tokenUrl", "https://psgeggxp8j.execute-api.eu-west-2.amazonaws.com/dev/token");
        passportStubCri.put(
                "credentialUrl",
                "https://psgeggxp8j.execute-api.eu-west-2.amazonaws.com/dev/credential");
        passportStubCri.put("ipvClientId", "IPV-Core");
        criList.add(passportDcsCri);
        return ApiGatewayResponseGenerator.proxyJsonResponse(200, criList);
    }
}
