package uk.gov.di.ipv.core.library.fixtures;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public interface TestFixtures {
    String EC_PRIVATE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthWhRANCAAQT1nO46ipxVTilUH2umZPN7OPI49GU6Y8YkcqLxFKUgypUzGbYR2VJGM+QJXk0PI339EyYkt6tjgfS+RcOMQNO";
    String EC_PRIVATE_KEY_JWK =
            "{\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}";
    String EC_PRIVATE_KEY_JWK_DOUBLE_ENCODED =
            "\"{\\\"kty\\\":\\\"EC\\\",\\\"d\\\":\\\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\\\",\\\"crv\\\":\\\"P-256\\\",\\\"x\\\":\\\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\\\",\\\"y\\\":\\\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\\\"}\"";
    String EC_PUBLIC_KEY =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIMqVMxm2EdlSRjPkCV5NDyN9/RMmJLerY4H0vkXDjEDTg==";
    String EC_PUBLIC_JWK =
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}";
    String EC_PUBLIC_JWK_2 =
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MjTFSolNjla11Dl8Zk9UpcpnMyWumfjIbO1E-0c8v-E\",\"y\":\"xTdKNukh5sOvMgNTKjo0hVYNNcAS-N7X1R1S0cjllTo\"}";

    String RSA_PRIVATE_KEY =
            "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";

    String RSA_PUBLIC_KEY =
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy1cVZ1KfFmgFlDQyf/R3LF/Js6jAS2Zzbs8WGSS0ys6Z+XR4x5DTIznZp5cHuuQmqOFylXSw5oGBwMXd2L6NimG9rJnJ4w8Gy5A6ImGsiDZC+3AXRBb5hq/IdDTBjbUqRxAKokSVwotWZt554BdSRPTmlYDujzxnClNKA06Xb/X3rTsgCUmZhUnSVtOzKytP3Bdv88VI5gq5tlZOtKXCB0PnJOqRbBmuL1RNkeTny4ZJW3I2ywSATwDDyDm4pJ8XGGNFKaYYTwr6uNTQ2VHb1FVC33oWbg+Zu9D4p5l7ONicCCF3V+GbvmyeCmHGnXznz0nYX1LFqaKtruEh3/GXyLy5X03Jzq6HhTf1SNFBmzziuCovhbR4v5aFDqAYNPWz+ajOdTUfP1I18c5jR1xGUxEiiLKBZWU1J5mhqCa+0CdI0mi3HwFmluudh47I2Xw++JiqZQpxRqNGcKJOPnWDgKOKXQ/ag37aJkxqoYWk9pQ/pXOdIKm//+B//8nWGo8BA/bfdmMHyzhWWxqtydjie2EZ5ODSdQ+yu1xU5cwP59BEQoU7FKVEGiJa4kzrsI2cgloUPlsPfLENMa5i09exDo//eDB/zNy9ACgGCriov1ex3uv4vHp3WtpZYe+akGEJeP0N5dejs0hkBuX+LUcM30TnQ424tEzcuaJ1F7r4FP0CAwEAAQ==";

    String RSA_ENCRYPTION_PUBLIC_JWK =
            "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}";

    String RSA_ENCRYPTION_PUBLIC_JWK_DOUBLE_ENCODED =
            "\"{\\\"kty\\\":\\\"RSA\\\",\\\"e\\\":\\\"AQAB\\\",\\\"n\\\":\\\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\\\"}\"";
    String RSA_ENCRYPTION_PRIVATE_KEY =
            "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC/JqmS8lcvClhEmNuRAP31XaBw8RQqs7d3CNwAD1M+Qu5xARm9hm9vv7B9IfGW8mUlx1LbSvk8oqap095bdjiKvdaxVV6KG3aI5lSt5Q7k7dXejsia8SM9L/b9kowcLBR/nVrpYY5oOM7zs5f9uW5XZ2nTWf4TeSIiXpGZYJXLCOfXd9feOxfQswIz9u3ceh8mqJiGE3KYTCHf2hH8PsQTmwtSKLZe+lNg9rov+4/B0pri9GXiHijCtYQlomJ8yisZy+qEIrUk4eqCSc3/dxv+ez0/HrKdAJ4Ve8EMnLirvVyWQGr8RmznbbtjVLbbbBcjBRg3zDlg5FB7cz6kIiHVAgMBAAECggEAdHFl7YlJSPOhT7BaWNvk2Lq/SO3jHhw6j/3KnxK23/+/5wEHoCer7MQ2DBRIam6g5UGmHMZwS9q9ckkJdGfxC7uXdJGPtMwECmNdhE08JIMpvJj4ZUKt99EnQdMrHOJRXmgKAI+YQ68Piu+FkF+McxwhIEn69/vbqlo3kdp/hZ2IhmMN6GTYFznj5E0N5/8kTFVZWCVtie5V2N0DosNeKqDcnKdB8rbY0vmHFAlKmhrXS+DKOI6O0+t9o1MUreThr1oMpegQbu1vayRpm8YAR6tfJ3UTVIhaywIcnsgmJf8EOcAlm9QlVYMB0bzVn4PyroNrXj/C6NRBqK7zrSh0ZQKBgQD7IlX8R7+b++ltpcBhzmcudCIsJyg6npCsXufanr4IaeFB/mrGfkEDC3ntOSXXbuoDnGDXZUhEsEYxp48nFBD3igrimn3epP6rqbbQA4YkLxzr41QjkBLhoBY3eQAX2Mdltah3ibCADsSYLu47ALOwXC92Qd+N45tEcHAyGxXbYwKBgQDC2s0SZc0q3lXk+lhDCYvrhqXOscl49lqQQTVWZWCQEmg1AZ0M+Ice9cSoMth5JZviRrkrt1FH+swCU5hb1H36zexkJEYX5Ie+27rqvvS7UW6ms5gQHUAGEESmoA2iJoaA6taNaHs6w9GB7E1Z/RFNCn81NZxuY4hFBgNFZji/ZwKBgCR57UFSbotKgLIzZAkQwL3nklsVaOtywpK2yjhf3Dw+nMBIItwn1GuLzC7foRZ0frr9iLdgd6m6bMejjdBgQsKho0kcpXGkR3VJlksKZ/5zdWDxyPPNZmCtLuzpv1C3ZObqBskuD5vaCUYNcv7Q8EiKaz5i/QSP7ap4JmOwuXD/An8hfXnBr72ToKMit+RzoTBrSrk0zVnTcIQgRxTjxIjUOlWuxpg3on+W0qb6QcLzD4O7YGxzFw7hUDnALJ4DKoJ8mOgITjO954ltRFbcAfYOO/DIthVsr5pRcHpcKSYuuHBlt/coVszXTNC1g+fHj7dphmRWwOAiGPlS47WsN+WJAoGBAPKQ30uMQ1kHUCiIabRKO0jLpHHE/yRbo+IdWek3gc9wQHq7xRgks8zUfWv4UWZVjmYaG1Rm3DVGy6AbWuPZThBByR3v7uM50F4ezY+UGCpxV0wwo8Si46/aSWQM0C7TxTMn1QhYu9W9kKL1DJKr721c0Rh3cuDPg/MJdSCRlMM0";

    String RSA_PUBLIC_CERT =
            "MIIFOjCCAyICCQDZiXCLK2ceNDANBgkqhkiG9w0BAQsFADBeMQswCQYDVQQGEwJVSzEPMA0GA1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xDDAKBgNVBAoMA0dEUzELMAkGA1UECwwCREkxEjAQBgNVBAMMCVRlc3QgY2VydDAgFw0yMjAzMzAxMzA4MzVaGA8yMTIyMDMwNjEzMDgzNVowXjELMAkGA1UEBhMCVUsxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQwwCgYDVQQKDANHRFMxCzAJBgNVBAsMAkRJMRIwEAYDVQQDDAlUZXN0IGNlcnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDLVxVnUp8WaAWUNDJ/9HcsX8mzqMBLZnNuzxYZJLTKzpn5dHjHkNMjOdmnlwe65Cao4XKVdLDmgYHAxd3Yvo2KYb2smcnjDwbLkDoiYayINkL7cBdEFvmGr8h0NMGNtSpHEAqiRJXCi1Zm3nngF1JE9OaVgO6PPGcKU0oDTpdv9fetOyAJSZmFSdJW07MrK0/cF2/zxUjmCrm2Vk60pcIHQ+ck6pFsGa4vVE2R5OfLhklbcjbLBIBPAMPIObiknxcYY0UpphhPCvq41NDZUdvUVULfehZuD5m70PinmXs42JwIIXdX4Zu+bJ4KYcadfOfPSdhfUsWpoq2u4SHf8ZfIvLlfTcnOroeFN/VI0UGbPOK4Ki+FtHi/loUOoBg09bP5qM51NR8/UjXxzmNHXEZTESKIsoFlZTUnmaGoJr7QJ0jSaLcfAWaW652HjsjZfD74mKplCnFGo0Zwok4+dYOAo4pdD9qDftomTGqhhaT2lD+lc50gqb//4H//ydYajwED9t92YwfLOFZbGq3J2OJ7YRnk4NJ1D7K7XFTlzA/n0ERChTsUpUQaIlriTOuwjZyCWhQ+Ww98sQ0xrmLT17EOj/94MH/M3L0AKAYKuKi/V7He6/i8enda2llh75qQYQl4/Q3l16OzSGQG5f4tRwzfROdDjbi0TNy5onUXuvgU/QIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAXlxmRPcewD9NxAUoi6XIxz/ly1ealJognL8UyjT+gHopJ7VSk1gyrMZ0j0XNl/IqdiEgPwoJCKGWJWbzl5EB3/HIorkNEK+fQjz73cmpAoe9+B9qdU/zL+kRrQTfN0hfUxPYOpescGL9wErE6F9Ajcz5gC8x7u9Qza2QCzu50Z/51duVIavjKHCqmEh+gWZCUDBJAXGVh0z9XvFyDCm17bFNSzdmIkbELtz6xM9Qq1xwweD3mIJ4kKFoz2hKEyESVyDw9qS7CqCzdAwEHnVE1rXfeCYWUOK4MdCnbkM3ZbKwCUC880fPrqWK9hFg5wSQcTfmJzoKCTnI1nQnx7nGbrTbK44SerS2+zkvBApDGfE3K9fpkgvW5Z77f0GBt+4hC5TsWPURkiGFisoQ1+QRlmXaOpc2EiqNkBF6MGftT34Sw9SPf8q3zih5BSZN9PGBevXQMA3by5cS1y6e8mPnB/0xUvmEqcASS+JqmUZS4OuqcIrvtzdhPcftv3H5IjRA46foTAS45WgoIwTA0OBpBBOnb1XayRfpT+vIqIeI78gsDsQa+qcOLIVo4Al/ftodb657B9hLbWcSoJ39JUXmZ26DPE32vzCfhCLDGMLZRfZixEOHprPzzwXjIJ6wW2SFVDi+d7S3LYJ0bm3h/yaJ3TI6m9hVcIKWZSY0aSTkZeA==";

    String VC_RESIDENCE_PERMIT_DCMAW =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Jldmlldy1kLnN0YWdpbmcuYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDpiMjcxYmExZi1kMzFjLTRjNjItOGE1Yi01ODMzODc1ODAxZmUiLCJuYmYiOjE3MDU0NjgyOTAsInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZGRyZXNzIjpbeyJ1cHJuIjoiMTAwMjI4MTI5MjkiLCJvcmdhbmlzYXRpb25OYW1lIjoiRklOQ0ggR1JPVVAiLCJzdWJCdWlsZGluZ05hbWUiOiJVTklUIDJCIiwiYnVpbGRpbmdOdW1iZXIgIjoiMTYiLCJidWlsZGluZ05hbWUiOiJDT1kgUE9ORCBCVVNJTkVTUyBQQVJLIiwiZGVwZW5kZW50U3RyZWV0TmFtZSI6IktJTkdTIFBBUksiLCJzdHJlZXROYW1lIjoiQklHIFNUUkVFVCIsImRvdWJsZURlcGVuZGVudEFkZHJlc3NMb2NhbGl0eSI6IlNPTUUgRElTVFJJQ1QiLCJkZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJMT05HIEVBVE9OIiwiYWRkcmVzc0xvY2FsaXR5IjoiR1JFQVQgTUlTU0VOREVOIiwicG9zdGFsQ29kZSI6IkhQMTYgMEFMIiwiYWRkcmVzc0NvdW50cnkiOiJHQiJ9XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NjUtMDctMDgifV0sInJlc2lkZW5jZVBlcm1pdCI6W3siaWNhb0lzc3VlckNvZGUiOiJHQlIiLCJkb2N1bWVudE51bWJlciI6IlpSODAxNjIwMCIsImV4cGlyeURhdGUiOiIyMDI0LTAyLTI1IiwiZG9jdW1lbnRUeXBlIjoiSVIifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiS2VubmV0aCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IkRlY2VycXVlaXJhIn1dfV19LCJldmlkZW5jZSI6W3sidHlwZSI6IklkZW50aXR5Q2hlY2siLCJ0eG4iOiJiY2QyMzQ2Iiwic3RyZW5ndGhTY29yZSI6MywidmFsaWRpdHlTY29yZSI6MiwiYWN0aXZpdHlIaXN0b3J5U2NvcmUiOiIxIiwiY2kiOltdLCJjaGVja0RldGFpbHMiOlt7ImNoZWNrTWV0aG9kIjoidnJpIiwiaWRlbnRpdHlDaGVja1BvbGljeSI6InB1Ymxpc2hlZCIsImFjdGl2aXR5RnJvbSI6IjIwMTktMDEtMDEifSx7ImNoZWNrTWV0aG9kIjoiYnZyIiwiYmlvbWV0cmljVmVyaWZpY2F0aW9uUHJvY2Vzc0xldmVsIjozfV19XX19.qwViFGeBFeUw3RCKuGm76V-qPAgQ0WVClE-qcS6Rebjv4Wbtikg1An4lVjEoX2ewWUov8fgif5s36InkmN06LQ";

    // As this is public test data you can generate VC signed JWTs using https://jwt.io/. Use the EC
    // public/private keys above to sign test VCs
    Map<String, Object> CREDENTIAL_ATTRIBUTES_1 =
            Map.of(
                    "name",
                    List.of(
                            Map.of(
                                    "nameParts",
                                    List.of(
                                            Map.of("value", "Alice", "type", "GivenName"),
                                            Map.of("value", "Jane", "type", "GivenName"),
                                            Map.of("value", "Laura", "type", "GivenName"),
                                            Map.of("value", "Doe", "type", "FamilyName"),
                                            Map.of("value", "Musk", "type", "FamilyName")))),
                    "birthDate",
                    List.of(Map.of("value", "2020-01-03"), Map.of("value", "2021-01-03")),
                    "address",
                    List.of(
                            Map.of(
                                    "buildingNumber", "10",
                                    "streetName", "DowningStreet",
                                    "dependentAddressLocality", "Westminster",
                                    "addressLocality", "London",
                                    "postalCode", "SW1A2AA",
                                    "addressCountry", "GB",
                                    "validFrom", "2019-07-24"),
                            Map.of(
                                    "buildingNumber", "123",
                                    "postalCode", "M34 1AA")),
                    "socialSecurityRecord",
                    List.of(Map.of("personalNumber", "AA000003D")));

    Map<String, Object> CREDENTIAL_ATTRIBUTES_2 =
            Map.of(
                    "name",
                    List.of(
                            Map.of(
                                    "nameParts",
                                    List.of(
                                            Map.of("value", "Alice", "type", "GivenName"),
                                            Map.of("value", "Doe", "type", "FamilyName")))),
                    "birthDate",
                    List.of(Map.of("value", "2020-01-03")),
                    "address",
                    List.of(
                            Map.of(
                                    "buildingNumber", "11",
                                    "streetName", "NotDowningStreet",
                                    "dependentAddressLocality", "Eastminster",
                                    "addressLocality", "Nodnol",
                                    "postalCode", "SW2A 3BB",
                                    "addressCountry", "GB",
                                    "validFrom", "2018-06-23")));

    Map<String, Object> CREDENTIAL_ATTRIBUTES_3 =
            Map.of(
                    "name",
                    List.of(
                            Map.of(
                                    "nameParts",
                                    List.of(
                                            Map.of("value", "Alice", "type", "GivenName"),
                                            Map.of("value", "Jane", "type", "GivenName"),
                                            Map.of("value", "Doe", "type", "FamilyName")))),
                    "birthDate",
                    List.of(Map.of("value", "2020-01-03")),
                    "address",
                    List.of(
                            Map.of(
                                    "buildingNumber", "11",
                                    "streetName", "NotDowningStreet",
                                    "dependentAddressLocality", "Eastminster",
                                    "addressLocality", "Nodnol",
                                    "postalCode", "SW2A 3BB",
                                    "addressCountry", "GB",
                                    "validFrom", "2018-06-23")));

    Map<String, Object> CREDENTIAL_ATTRIBUTES_4 =
            Map.of(
                    "name",
                    List.of(
                            Map.of(
                                    "nameParts",
                                    List.of(
                                            Map.of("value", "Alice", "type", "GivenName"),
                                            Map.of("value", "Jane", "type", "GivenName"),
                                            Map.of("value", "Doe", "type", "FamilyName"))),
                            Map.of(
                                    "nameParts",
                                    List.of(
                                            Map.of("value", "Alice", "type", "GivenName"),
                                            Map.of("value", "Jane", "type", "GivenName"),
                                            Map.of("value", "Laura", "type", "GivenName"),
                                            Map.of("value", "Doe", "type", "FamilyName"),
                                            Map.of("value", "Musk", "type", "FamilyName")))),
                    "birthDate",
                    List.of(Map.of("value", "2020-01-03")),
                    "address",
                    List.of(
                            Map.of(
                                    "buildingNumber", "11",
                                    "streetName", "NotDowningStreet",
                                    "dependentAddressLocality", "Eastminster",
                                    "addressLocality", "Nodnol",
                                    "postalCode", "SW2A 3BB",
                                    "addressCountry", "GB",
                                    "validFrom", "2018-06-23")));

    Map<String, Object> PASSPORT_CREDENTIAL_ATTRIBUTES =
            Map.of(
                    "name",
                    List.of(
                            Map.of(
                                    "nameParts",
                                    List.of(
                                            Map.of("value", "Mary", "type", "GivenName"),
                                            Map.of("value", "Watson", "type", "FamilyName")))),
                    "birthDate",
                    List.of(Map.of("value", "1932-02-25")),
                    "passport",
                    List.of(
                            Map.of(
                                    "documentNumber", "824159121",
                                    "expiryDate", "2030-01-01")));

    String ADDRESS_JSON_1 =
            "{\"buildingNumber\":10,\"streetName\":\"DowningStreet\",\"dependentAddressLocality\":\"Westminster\",\"addressLocality\":\"London\",\"postalCode\":\"SW1A2AA\",\"addressCountry\":\"GB\",\"validFrom\":\"2019-07-24\"}";
    String ADDRESS_JSON_2 =
            "{\"buildingNumber\":11,\"streetName\":\"DowningStreet\",\"dependentAddressLocality\":\"Westminster\",\"addressLocality\":\"London\",\"postalCode\":\"SW1A2AA\",\"addressCountry\":\"GB\",\"validFrom\":\"2019-07-24\"}";
    String PASSPORT_JSON_1 = "{\"documentNumber\":12345678,\"expiryDate\":\"2022-02-01\"}";

    String DRIVING_PERMIT_JSON_1 =
            "{\"personalNumber\": \"DOE99802085J99FG\",\"fullAddress\": \"122 BURNS CRESCENT EDINBURGH EH1 9GP\",\"expiryDate\": \"2023-01-18\",\"issueNumber\": 5,\"issuedBy\": \"DVLA\",\"issueDate\": \"2010-01-18\"}";

    String NINO_JSON_1 = "{\"personalNumber\": \"AA000003D\"}";

    String SIGNED_JWT =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJBdWRpZW5jZSIsInN1YiI6InRlc3RDbGllbnRJZCIsIm5iZiI6MTY1MTY3MzQ3NCwic2hhcmVkX2NsYWltcyI6eyJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6bnVsbCwib3JnYW5pemF0aW9uTmFtZSI6bnVsbCwic3RyZWV0QWRkcmVzcyI6bnVsbCwicG9zdGFsQ29kZSI6bnVsbCwiYWRkcmVzc0xvY2FsaXR5IjpudWxsLCJ0eXBlIjpudWxsLCJhZGRyZXNzUmVnaW9uIjpudWxsfV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidmFsaWRVbnRpbCI6bnVsbCwidmFsaWRGcm9tIjpudWxsLCJ0eXBlIjoiZmlyc3RfbmFtZSIsInZhbHVlIjoiRGFuIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIyMDExLTAxLTAxIn1dfSwiaXNzIjoidGVzdENsaWVudElkIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJyZWRpcmVjdF91cmkiOiJjYWxsYmFja1VyaT9pZD1jcmlfaWQiLCJzdGF0ZSI6InJlYWQiLCJleHAiOjE2NTE2NzQzNzQsImlhdCI6MTY1MTY3MzQ3NCwiY2xpZW50X2lkIjoidGVzdENsaWVudElkIn0.jfYDzFJjANSkwC7Zxd45aJBzv8dgXNRdi3oWvFUEg3aWWfXW6a-R29CDrCZZXNueoOEQFjkz88R5Az0urnohgw";

    String DER_SIGNATURE =
            "MEYCIQDnbeWakZ7xcj2NmlXyv2gr_qcewMibItnKT9NDo2xY8gIhANGye8Itd-0sy1W7ejQz9volzX7UU0zBrHuMFTzb_jNz";

    String SIGNED_CONTRA_INDICATOR_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhLXVzZXItaWQiLCJuYmYiOjE2ODk5NDMxNjgsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkuc3RhZ2luZy5hY2NvdW50Lmdvdi51ayIsImV4cCI6MjAwNTMwMzE2OCwiaWF0IjoxNjg5OTQzMTY5LCJ2YyI6eyJldmlkZW5jZSI6W3siY29udHJhSW5kaWNhdG9yIjpbeyJtaXRpZ2F0aW9uIjpbeyJtaXRpZ2F0aW5nQ3JlZGVudGlhbCI6W3sidmFsaWRGcm9tIjoiMjAyMi0wOS0yMVQxNTo1NDo1MC4wMDBaIiwidHhuIjoiZ2hpaiIsImlkIjoidXJuOnV1aWQ6ZjgxZDRmYWUtN2RlYy0xMWQwLWE3NjUtMDBhMGM5MWU2YmY2IiwiaXNzdWVyIjoiaHR0cHM6Ly9jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLyJ9XSwiY29kZSI6Ik0wMSJ9XSwiY29kZSI6IkQwMSIsImlzc3VlcnMiOlsiaHR0cHM6Ly9pc3N1aW5nLWNyaS5leGFtcGxlIl0sImluY29tcGxldGVNaXRpZ2F0aW9uIjpbeyJtaXRpZ2F0aW5nQ3JlZGVudGlhbCI6W3sidmFsaWRGcm9tIjoiMjAyMi0wOS0yMlQxNTo1NDo1MC4wMDBaIiwidHhuIjoiY2RlZWYiLCJpZCI6InVybjp1dWlkOmY1YzlmZjQwLTFkY2QtNGE4Yi1iZjkyLTk0NTYwNDdjMTMyZiIsImlzc3VlciI6Imh0dHBzOi8vYW5vdGhlci1jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLyJ9XSwiY29kZSI6Ik0wMiJ9XSwiaXNzdWFuY2VEYXRlIjoiMjAyMi0wOS0yMFQxNTo1NDo1MC4wMDBaIiwiZG9jdW1lbnQiOiJwYXNzcG9ydC9HQlIvODI0MTU5MTIxIiwidHhuIjpbImFiY2RlZiJdfV0sInR4biI6WyJma2ZrZCJdLCJ0eXBlIjoiU2VjdXJpdHlDaGVjayJ9XSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlNlY3VyaXR5Q2hlY2tDcmVkZW50aWFsIl19fQo.x983z-9YFktlkiq3d_400HD04VXgB99TyFPjDZ3qnpxnzC3B7wdXPdVBu1K2aRR1YmuWBx43HNsvWVMfJecjMQ";

    String SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkZW50aXR5LnN0YWdpbmcuYWNjb3VudC5nb3YudWsiLCJpYXQiOjE2ODgxMjM0NjYsIm5iZiI6MTY4ODEyMzQ2NiwiZXhwIjoyMDAzNDgzNDY2LCJzdWIiOiJhLXVzZXItaWQiLCJ2YyI6eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiU2VjdXJpdHlDaGVja0NyZWRlbnRpYWwiXSwiZXZpZGVuY2UiOltdfX0.licS4NM0EWKQm6fYT1plBQV6Bk4e9qrdXQ1NOo-GIvmTUhPbRSXHdUvGHUNbnVFxFZMyxdtBM_lkEUfqTpY64A";

    String SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkZW50aXR5LnN0YWdpbmcuYWNjb3VudC5nb3YudWsiLCJpYXQiOjE2ODgxMjUwNDAsIm5iZiI6MTY4ODEyNTAzOSwiZXhwIjoyMDAzNDg1MDM5LCJzdWIiOiJhLXVzZXItaWQiLCJ2YyI6eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiU2VjdXJpdHlDaGVja0NyZWRlbnRpYWwiXSwiZXZpZGVuY2UiOlt7InR5cGUiOiJTZWN1cml0eUNoZWNrIiwibm90QUNvbnRyYUluZGljYXRvciI6W3siY29kZSI6IkQwMSIsImlzc3VhbmNlRGF0ZSI6IjIwMjItMDktMjBUMTU6NTQ6NTAuMDAwWiIsImRvY3VtZW50IjoicGFzc3BvcnQvR0JSLzgyNDE1OTEyMSIsInR4biI6WyJhYmNkZWYiXSwibWl0aWdhdGlvbiI6W3siY29kZSI6Ik0wMSIsIm1pdGlnYXRpbmdDcmVkZW50aWFsIjpbeyJpc3N1ZXIiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUvIiwidmFsaWRGcm9tIjoiMjAyMi0wOS0yMVQxNTo1NDo1MC4wMDBaIiwidHhuIjoiZ2hpaiIsImlkIjoidXJuOnV1aWQ6ZjgxZDRmYWUtN2RlYy0xMWQwLWE3NjUtMDBhMGM5MWU2YmY2In1dfV0sImluY29tcGxldGVNaXRpZ2F0aW9uIjpbeyJjb2RlIjoiTTAyIiwibWl0aWdhdGluZ0NyZWRlbnRpYWwiOlt7Imlzc3VlciI6Imh0dHBzOi8vYW5vdGhlci1jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLyIsInZhbGlkRnJvbSI6IjIwMjItMDktMjJUMTU6NTQ6NTAuMDAwWiIsInR4biI6ImNkZWVmIiwiaWQiOiJ1cm46dXVpZDpmNWM5ZmY0MC0xZGNkLTRhOGItYmY5Mi05NDU2MDQ3YzEzMmYifV19XX1dfV19fQ._2dCakEuFyF861YIxn7XJvBs03vbmPfX3H51YuUyn53sFDKJPZZzgAN_qMIphEfTlUMxclKtCu0b_ycseW3bFQ";

    String SIGNED_CONTRA_INDICATOR_NO_VC =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.JEB0XsBplsmqz18ntjz_0hpDhjBus1HNvU280S7Mcjo";

    static JWEObject createJweObject(RSAEncrypter rsaEncrypter, SignedJWT signedJWT)
            throws HttpResponseExceptionWithErrorBody {
        try {
            JWEObject jweObject =
                    new JWEObject(
                            new JWEHeader.Builder(
                                            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT")
                                    .build(),
                            new Payload(signedJWT));
            jweObject.encrypt(rsaEncrypter);
            return jweObject;
        } catch (JOSEException e) {
            throw new HttpResponseExceptionWithErrorBody(500, ErrorResponse.FAILED_TO_ENCRYPT_JWT);
        }
    }

    static VcStoreItem createVcStoreItem(
            String userId, String credentialIssuer, String credential) {
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId(userId);
        vcStoreItem.setCredentialIssuer(credentialIssuer);
        vcStoreItem.setCredential(credential);
        Instant dateCreated = Instant.now();
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }

    static VcStoreItem createInvalidVcStoreItem(
            String userId, String credentialIssuer, String credential) {
        return createVcStoreItem(userId, credentialIssuer, credential);
    }
}
