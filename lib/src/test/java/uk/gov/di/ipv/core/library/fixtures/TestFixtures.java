package uk.gov.di.ipv.core.library.fixtures;

import java.util.List;
import java.util.Map;

public interface TestFixtures {
    String EC_PRIVATE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthWhRANCAAQT1nO46ipxVTilUH2umZPN7OPI49GU6Y8YkcqLxFKUgypUzGbYR2VJGM+QJXk0PI339EyYkt6tjgfS+RcOMQNO";
    String EC_PRIVATE_KEY_JWK =
            "{\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}";
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

    String RSA_ENCRYPTION_PRIVATE_KEY =
            "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC/JqmS8lcvClhEmNuRAP31XaBw8RQqs7d3CNwAD1M+Qu5xARm9hm9vv7B9IfGW8mUlx1LbSvk8oqap095bdjiKvdaxVV6KG3aI5lSt5Q7k7dXejsia8SM9L/b9kowcLBR/nVrpYY5oOM7zs5f9uW5XZ2nTWf4TeSIiXpGZYJXLCOfXd9feOxfQswIz9u3ceh8mqJiGE3KYTCHf2hH8PsQTmwtSKLZe+lNg9rov+4/B0pri9GXiHijCtYQlomJ8yisZy+qEIrUk4eqCSc3/dxv+ez0/HrKdAJ4Ve8EMnLirvVyWQGr8RmznbbtjVLbbbBcjBRg3zDlg5FB7cz6kIiHVAgMBAAECggEAdHFl7YlJSPOhT7BaWNvk2Lq/SO3jHhw6j/3KnxK23/+/5wEHoCer7MQ2DBRIam6g5UGmHMZwS9q9ckkJdGfxC7uXdJGPtMwECmNdhE08JIMpvJj4ZUKt99EnQdMrHOJRXmgKAI+YQ68Piu+FkF+McxwhIEn69/vbqlo3kdp/hZ2IhmMN6GTYFznj5E0N5/8kTFVZWCVtie5V2N0DosNeKqDcnKdB8rbY0vmHFAlKmhrXS+DKOI6O0+t9o1MUreThr1oMpegQbu1vayRpm8YAR6tfJ3UTVIhaywIcnsgmJf8EOcAlm9QlVYMB0bzVn4PyroNrXj/C6NRBqK7zrSh0ZQKBgQD7IlX8R7+b++ltpcBhzmcudCIsJyg6npCsXufanr4IaeFB/mrGfkEDC3ntOSXXbuoDnGDXZUhEsEYxp48nFBD3igrimn3epP6rqbbQA4YkLxzr41QjkBLhoBY3eQAX2Mdltah3ibCADsSYLu47ALOwXC92Qd+N45tEcHAyGxXbYwKBgQDC2s0SZc0q3lXk+lhDCYvrhqXOscl49lqQQTVWZWCQEmg1AZ0M+Ice9cSoMth5JZviRrkrt1FH+swCU5hb1H36zexkJEYX5Ie+27rqvvS7UW6ms5gQHUAGEESmoA2iJoaA6taNaHs6w9GB7E1Z/RFNCn81NZxuY4hFBgNFZji/ZwKBgCR57UFSbotKgLIzZAkQwL3nklsVaOtywpK2yjhf3Dw+nMBIItwn1GuLzC7foRZ0frr9iLdgd6m6bMejjdBgQsKho0kcpXGkR3VJlksKZ/5zdWDxyPPNZmCtLuzpv1C3ZObqBskuD5vaCUYNcv7Q8EiKaz5i/QSP7ap4JmOwuXD/An8hfXnBr72ToKMit+RzoTBrSrk0zVnTcIQgRxTjxIjUOlWuxpg3on+W0qb6QcLzD4O7YGxzFw7hUDnALJ4DKoJ8mOgITjO954ltRFbcAfYOO/DIthVsr5pRcHpcKSYuuHBlt/coVszXTNC1g+fHj7dphmRWwOAiGPlS47WsN+WJAoGBAPKQ30uMQ1kHUCiIabRKO0jLpHHE/yRbo+IdWek3gc9wQHq7xRgks8zUfWv4UWZVjmYaG1Rm3DVGy6AbWuPZThBByR3v7uM50F4ezY+UGCpxV0wwo8Si46/aSWQM0C7TxTMn1QhYu9W9kKL1DJKr721c0Rh3cuDPg/MJdSCRlMM0";

    String RSA_PUBLIC_CERT =
            "MIIFOjCCAyICCQDZiXCLK2ceNDANBgkqhkiG9w0BAQsFADBeMQswCQYDVQQGEwJVSzEPMA0GA1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xDDAKBgNVBAoMA0dEUzELMAkGA1UECwwCREkxEjAQBgNVBAMMCVRlc3QgY2VydDAgFw0yMjAzMzAxMzA4MzVaGA8yMTIyMDMwNjEzMDgzNVowXjELMAkGA1UEBhMCVUsxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQwwCgYDVQQKDANHRFMxCzAJBgNVBAsMAkRJMRIwEAYDVQQDDAlUZXN0IGNlcnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDLVxVnUp8WaAWUNDJ/9HcsX8mzqMBLZnNuzxYZJLTKzpn5dHjHkNMjOdmnlwe65Cao4XKVdLDmgYHAxd3Yvo2KYb2smcnjDwbLkDoiYayINkL7cBdEFvmGr8h0NMGNtSpHEAqiRJXCi1Zm3nngF1JE9OaVgO6PPGcKU0oDTpdv9fetOyAJSZmFSdJW07MrK0/cF2/zxUjmCrm2Vk60pcIHQ+ck6pFsGa4vVE2R5OfLhklbcjbLBIBPAMPIObiknxcYY0UpphhPCvq41NDZUdvUVULfehZuD5m70PinmXs42JwIIXdX4Zu+bJ4KYcadfOfPSdhfUsWpoq2u4SHf8ZfIvLlfTcnOroeFN/VI0UGbPOK4Ki+FtHi/loUOoBg09bP5qM51NR8/UjXxzmNHXEZTESKIsoFlZTUnmaGoJr7QJ0jSaLcfAWaW652HjsjZfD74mKplCnFGo0Zwok4+dYOAo4pdD9qDftomTGqhhaT2lD+lc50gqb//4H//ydYajwED9t92YwfLOFZbGq3J2OJ7YRnk4NJ1D7K7XFTlzA/n0ERChTsUpUQaIlriTOuwjZyCWhQ+Ww98sQ0xrmLT17EOj/94MH/M3L0AKAYKuKi/V7He6/i8enda2llh75qQYQl4/Q3l16OzSGQG5f4tRwzfROdDjbi0TNy5onUXuvgU/QIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAXlxmRPcewD9NxAUoi6XIxz/ly1ealJognL8UyjT+gHopJ7VSk1gyrMZ0j0XNl/IqdiEgPwoJCKGWJWbzl5EB3/HIorkNEK+fQjz73cmpAoe9+B9qdU/zL+kRrQTfN0hfUxPYOpescGL9wErE6F9Ajcz5gC8x7u9Qza2QCzu50Z/51duVIavjKHCqmEh+gWZCUDBJAXGVh0z9XvFyDCm17bFNSzdmIkbELtz6xM9Qq1xwweD3mIJ4kKFoz2hKEyESVyDw9qS7CqCzdAwEHnVE1rXfeCYWUOK4MdCnbkM3ZbKwCUC880fPrqWK9hFg5wSQcTfmJzoKCTnI1nQnx7nGbrTbK44SerS2+zkvBApDGfE3K9fpkgvW5Z77f0GBt+4hC5TsWPURkiGFisoQ1+QRlmXaOpc2EiqNkBF6MGftT34Sw9SPf8q3zih5BSZN9PGBevXQMA3by5cS1y6e8mPnB/0xUvmEqcASS+JqmUZS4OuqcIrvtzdhPcftv3H5IjRA46foTAS45WgoIwTA0OBpBBOnb1XayRfpT+vIqIeI78gsDsQa+qcOLIVo4Al/ftodb657B9hLbWcSoJ39JUXmZ26DPE32vzCfhCLDGMLZRfZixEOHprPzzwXjIJ6wW2SFVDi+d7S3LYJ0bm3h/yaJ3TI6m9hVcIKWZSY0aSTkZeA==";

    String SIGNED_VC_1 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciIsInN1YiI6InRlc3Qtc3ViamVjdCIsIm5iZiI6MTY1Mjk1MTA1NCwiZXhwIjoxNjUzMDUxMDU0LCJ2YyI6eyJldmlkZW5jZSI6W3sidmFsaWRpdHlTY29yZSI6Miwic3RyZW5ndGhTY29yZSI6NCwiY2kiOm51bGwsInR4biI6IjFlMGYyOGM1LTYzMjktNDZmMC1iZjBlLTgzM2NiOWI1OGM5ZSIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJwYXNzcG9ydCI6W3siZXhwaXJ5RGF0ZSI6IjIwMjAtMDEtMDEiLCJkb2N1bWVudE51bWJlciI6IjEyMzQ1Njc4OSJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJQYXVsIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIyMDIwLTAyLTAzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.1piP6FwpWvh7ianTDRTKCPhKMGqDu6YCKZ8z5onv7DXHjDEumGvQs803nrKLH0n36GPt1a9M6dBctemgEDoecQ";
    String SIGNED_VC_2 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyLWlkIiwiYXVkIjoiaHR0cHM6XC9cL2V4YW1wbGUuY29tXC9hdWRpZW5jZSIsIm5iZiI6MTY1Mjk1MzIwMywiaXNzIjoiaHR0cHM6XC9cL2lzc3Vlci5leGFtcGxlLmNvbSIsImV4cCI6MTY1Mjk1MzUwMywidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidmFsdWUiOiJDaHJpcyIsInR5cGUiOiJHaXZlbk5hbWUifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5ODQtMDktMjgifV0sImFkZHJlc3MiOlt7InR5cGUiOiJQb3N0YWxBZGRyZXNzIiwicG9zdGFsQ29kZSI6IkxFMTIgOUJOIn1dfSwiZXZpZGVuY2UiOlt7InR4biI6InNvbWUtdXVpZCIsImlkZW50aXR5RnJhdWRTY29yZSI6MSwidHlwZSI6IkNyaVN0dWJDaGVjayJ9XX19.GFO94sTQmb2ylYRZruvU8D_fEh9QQUr9-BTV6Thuv7roB8cOchit5YJfcta1IEoOSVRLewT_75D_YsjDNNUhew";
    String SIGNED_VC_3 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyLWlkIiwiYXVkIjoiaHR0cHM6XC9cL2V4YW1wbGUuY29tXC9hdWRpZW5jZSIsIm5iZiI6MTY1Mjk1MzA4MCwiaXNzIjoiaHR0cHM6XC9cL2lzc3Vlci5leGFtcGxlLmNvbSIsImV4cCI6MTY1Mjk1MzM4MCwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiQ2hyaXMifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5ODQtMDktMjgifV0sImFkZHJlc3MiOlt7InR5cGUiOiJQb3N0YWxBZGRyZXNzIiwicG9zdGFsQ29kZSI6IkxFMTIgOUJOIn1dfSwiZXZpZGVuY2UiOlt7InR4biI6InNvbWUtdXVpZCIsInR5cGUiOiJDcmlTdHViQ2hlY2siLCJ2ZXJpZmljYXRpb25TY29yZSI6Mn1dfX0.So2GWIfKbewlXyVdOcjdgi4GQ67OrrismelIoMpQdamOOepkc8KK0vsb25BZTuAFQSKUIpviu9MqCUIAIXr12g";
    String SIGNED_VC_4 =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6Imh0dHBzOi8vc3ViamVjdC5leGFtcGxlLmNvbSIsIm5iZiI6MTY0NzQzMzMwOSwiZXhwIjoxNjQ3NDMzOTA5LCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdm9jYWIubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsL2NvbnRleHRzL2lkZW50aXR5LXYxLmpzb25sZCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWRkcmVzcyI6W3siYWRkcmVzc1JlZ2lvbiI6IklsbGlub2lzIiwic3RyZWV0QWRkcmVzcyI6IjM1IElkc3dvcnRoIFJvYWQiLCJhZGRyZXNzTG9jYWxpdHkiOiJTaGVmZmllbGQiLCJ0eXBlIjoiUG9zdGFsQWRkcmVzcyIsImFkZHJlc3NDb3VudHJ5IjoiVUsiLCJvcmdhbml6YXRpb25OYW1lIjoiU29mdHdhcmUgTHRkIiwicG9zdGFsQ29kZSI6IlM1IDZVTiJ9XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjIwMjAtMDEtMDMifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiQWxpY2UifSx7InZhbGlkRnJvbSI6IjIwMjAtMDMtMDEiLCJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiRG9lIn1dfV19LCJldmlkZW5jZSI6W3sidmVyaWZpY2F0aW9uIjowfV19fQ.5BEUZ27M-u2zlNZ7Y7mgsmdKKXkmDd_5uqqK9omXcAE";
    String SIGNED_VC_5 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDphYmY0MmZhZi0wNTcyLTRjN2YtYjhhMC1mZDk4NjY3YmVlYWMiLCJhdWQiOiJodHRwczpcL1wvaWRlbnRpdHkuc3RhZ2luZy5hY2NvdW50Lmdvdi51ayIsIm5iZiI6MTY1MzMxNzQ3NywiaXNzIjoiaHR0cHM6XC9cL3Jldmlldy1wLnN0YWdpbmcuYWNjb3VudC5nb3YudWsiLCJleHAiOjE2NTMzMTk4NzcsInZjIjp7ImV2aWRlbmNlIjpbeyJ2YWxpZGl0eVNjb3JlIjoyLCJzdHJlbmd0aFNjb3JlIjo0LCJjaSI6bnVsbCwidHhuIjoiMWU1MDU2YmYtZTQ0OC00Y2YyLTgwNjYtMWM5ODNjYTNjNjQyIiwidHlwZSI6IklkZW50aXR5Q2hlY2sifV0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7InBhc3Nwb3J0IjpbeyJleHBpcnlEYXRlIjoiMjAyMS0wMy0wMSIsImRvY3VtZW50TnVtYmVyIjoiODI0MTU5MTIxIn1dLCJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6Ik1hcnkifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJXYXRzb24ifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5MzItMDItMjUifV19LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXX19.MEUCIEvlpbJwjpQtyHyBTaKAMD3mnmROxXaF1qrhBT0NQrk7AiEAu1uoNKIa0tdzvG61VDFJpoHXXFJwS0qnaYBWanmtJjo";
    String SIGNED_PASSPORT_VC_MISSING_NAME =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciIsInN1YiI6InRlc3Qtc3ViamVjdCIsIm5iZiI6MTY1Mjk1MTA1NCwiZXhwIjoxNjUzMDUxMDU0LCJ2YyI6eyJldmlkZW5jZSI6W3sidmFsaWRpdHlTY29yZSI6Miwic3RyZW5ndGhTY29yZSI6NCwiY2kiOm51bGwsInR4biI6IjFlMGYyOGM1LTYzMjktNDZmMC1iZjBlLTgzM2NiOWI1OGM5ZSIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJwYXNzcG9ydCI6W3siZXhwaXJ5RGF0ZSI6IjIwMjAtMDEtMDEiLCJkb2N1bWVudE51bWJlciI6IjEyMzQ1Njc4OSJ9XSwiaW52YWxpZE5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiUGF1bCJ9XX1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMjAyMC0wMi0wMyJ9XX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdfX0.EpbTgsB_UYeug6RhOk-jWQo3GzEuTG7JDYpBuNxKQugD3IsgfRozlOCztb0sAkWODV4DTtSdOpdnBXoS-0yCIA";
    String SIGNED_PASSPORT_VC_MISSING_BIRTH_DATE =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciIsInN1YiI6InRlc3Qtc3ViamVjdCIsIm5iZiI6MTY1Mjk1MTA1NCwiZXhwIjoxNjUzMDUxMDU0LCJ2YyI6eyJldmlkZW5jZSI6W3sidmFsaWRpdHlTY29yZSI6Miwic3RyZW5ndGhTY29yZSI6NCwiY2kiOm51bGwsInR4biI6IjFlMGYyOGM1LTYzMjktNDZmMC1iZjBlLTgzM2NiOWI1OGM5ZSIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJwYXNzcG9ydCI6W3siZXhwaXJ5RGF0ZSI6IjIwMjAtMDEtMDEiLCJkb2N1bWVudE51bWJlciI6IjEyMzQ1Njc4OSJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJQYXVsIn1dfV0sImludmFsaWRCaXJ0aERhdGUiOlt7InZhbHVlIjoiMjAyMC0wMi0wMyJ9XX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdfX0.UnSyl0Nvy5GKLWHAZ4U2b6g0M2WjJQtRZm3Lwzo-uO6g0N-56L_C37Tl5tJ5TFQ3AIEcFVVcZxrDVtfdprR4hg";
    String SIGNED_KBV_VC_PASSED =
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJhdWQiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2F1ZGllbmNlIiwibmJmIjoxNjUzNDAyMjQwLCJpc3MiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2lzc3VlciIsImV4cCI6MTY1MzQwMzE0MCwidmMiOnsiZXZpZGVuY2UiOlt7InZlcmlmaWNhdGlvblNjb3JlIjoyLCJ0eG4iOiJhYmMxMjM0IiwidHlwZSI6IklkZW50aXR5Q2hlY2sifV0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJ1cHJuIjoiMTAwMjI4MTI5MjkiLCJidWlsZGluZ05hbWUiOiJDT1lQT05EQlVTSU5FU1NQQVJLIiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIR1JPVVAiLCJzdHJlZXROYW1lIjoiQklHU1RSRUVUIiwiZGVwZW5kZW50U3RyZWV0TmFtZSI6IktJTkdTUEFSSyIsInBvc3RhbENvZGUiOiJIUDE2MEFMIiwiYnVpbGRpbmdOdW1iZXIiOiIxNiIsImRlcGVuZGVudEFkZHJlc3NMb2NhbGl0eSI6IkxPTkdFQVRPTiIsImFkZHJlc3NMb2NhbGl0eSI6IkdSRUFUTUlTU0VOREVOIiwiZG91YmxlRGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiU09NRURJU1RSSUNUIiwic3ViQnVpbGRpbmdOYW1lIjoiVU5JVDJCIn1dLCJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IkFsaWNlIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiRG9lIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTcwLTAxLTAxIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.TpaDlOVVDcYFerwpejdVkDY2EIeb9T7DPRRsYiBNsaV6Sc1ueZPycfs3WMs2gVB-7ik_KFwSTwz_YwNPlEBe3w";
    String SIGNED_KBV_VC_FAILED =
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJhdWQiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2F1ZGllbmNlIiwibmJmIjoxNjUzNDAyMzA5LCJpc3MiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2lzc3VlciIsImV4cCI6MTY1MzQwMzIwOSwidmMiOnsiZXZpZGVuY2UiOlt7InZlcmlmaWNhdGlvblNjb3JlIjowLCJ0eG4iOiJhYmMxMjM0IiwidHlwZSI6IklkZW50aXR5Q2hlY2sifV0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJ1cHJuIjoiMTAwMjI4MTI5MjkiLCJidWlsZGluZ05hbWUiOiJDT1lQT05EQlVTSU5FU1NQQVJLIiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIR1JPVVAiLCJzdHJlZXROYW1lIjoiQklHU1RSRUVUIiwiZGVwZW5kZW50U3RyZWV0TmFtZSI6IktJTkdTUEFSSyIsInBvc3RhbENvZGUiOiJIUDE2MEFMIiwiYnVpbGRpbmdOdW1iZXIiOiIxNiIsImRlcGVuZGVudEFkZHJlc3NMb2NhbGl0eSI6IkxPTkdFQVRPTiIsImFkZHJlc3NMb2NhbGl0eSI6IkdSRUFUTUlTU0VOREVOIiwiZG91YmxlRGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiU09NRURJU1RSSUNUIiwic3ViQnVpbGRpbmdOYW1lIjoiVU5JVDJCIn1dLCJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IkFsaWNlIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiRG9lIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTcwLTAxLTAxIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.90sSVh2JzcE-SULetoRBKbq7_Eh6KhVo0M6JS6FqklUE9AbTUPt2FxPvVWQxXJZCMJI04CrKeqbJ0GGUDh0LrQ";
    String SIGNED_FRAUD_VC_PASSED =
            "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2F1ZGllbmNlIiwic3ViIjoidGVzdC1zdWJqZWN0IiwibmJmIjoxNjUzNDA2NTU0LCJpc3MiOiJodHRwczpcL1wvZXhhbXBsZXMuY29tXC9pc3N1ZXIiLCJleHAiOjE2NTM0MDc0NTQsInZjIjp7ImV2aWRlbmNlIjpbeyJ0eG4iOiJhYmMxMjM0IiwiaWRlbnRpdHlGcmF1ZFNjb3JlIjoxLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayJ9XSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWRkcmVzcyI6W3siYWRkcmVzc0NvdW50cnkiOiJHQiIsInVwcm4iOiIxMDAyMjgxMjkyOSIsImJ1aWxkaW5nTmFtZSI6IkNPWVBPTkRCVVNJTkVTU1BBUksiLCJvcmdhbmlzYXRpb25OYW1lIjoiRklOQ0hHUk9VUCIsInN0cmVldE5hbWUiOiJCSUdTVFJFRVQiLCJkZXBlbmRlbnRTdHJlZXROYW1lIjoiS0lOR1NQQVJLIiwicG9zdGFsQ29kZSI6IkhQMTYwQUwiLCJidWlsZGluZ051bWJlciI6IjE2IiwiZGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiTE9OR0VBVE9OIiwiYWRkcmVzc0xvY2FsaXR5IjoiR1JFQVRNSVNTRU5ERU4iLCJkb3VibGVEZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJTT01FRElTVFJJQ1QiLCJzdWJCdWlsZGluZ05hbWUiOiJVTklUMkIifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiQWxpY2UifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJEb2UifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NzAtMDEtMDEifV19LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXX19.gDM4Zm8rSv7PiXZakcD5oqkR7cyMZNdzAM6Gjew44LZ3xDYexMRZaekDBLrqh54wh-f-AGKxmXk0wrE-3yCAuA";
    String SIGNED_FRAUD_VC_WITH_CI =
            "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2F1ZGllbmNlIiwic3ViIjoidGVzdC1zdWJqZWN0IiwibmJmIjoxNjUzNDA2NjUwLCJpc3MiOiJodHRwczpcL1wvZXhhbXBsZXMuY29tXC9pc3N1ZXIiLCJleHAiOjE2NTM0MDc1NTAsInZjIjp7ImV2aWRlbmNlIjpbeyJjaSI6WyJGMDQiXSwidHhuIjoiYWJjMTIzNCIsImlkZW50aXR5RnJhdWRTY29yZSI6MSwidHlwZSI6IklkZW50aXR5Q2hlY2sifV0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJ1cHJuIjoiMTAwMjI4MTI5MjkiLCJidWlsZGluZ05hbWUiOiJDT1lQT05EQlVTSU5FU1NQQVJLIiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIR1JPVVAiLCJzdHJlZXROYW1lIjoiQklHU1RSRUVUIiwiZGVwZW5kZW50U3RyZWV0TmFtZSI6IktJTkdTUEFSSyIsInBvc3RhbENvZGUiOiJIUDE2MEFMIiwiYnVpbGRpbmdOdW1iZXIiOiIxNiIsImRlcGVuZGVudEFkZHJlc3NMb2NhbGl0eSI6IkxPTkdFQVRPTiIsImFkZHJlc3NMb2NhbGl0eSI6IkdSRUFUTUlTU0VOREVOIiwiZG91YmxlRGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiU09NRURJU1RSSUNUIiwic3ViQnVpbGRpbmdOYW1lIjoiVU5JVDJCIn1dLCJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IkFsaWNlIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiRG9lIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTcwLTAxLTAxIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.Lvpqg6nuWHk6koUdDvANavoRDV12TqomPpqXTsEbNSou_J2aFJhpe9GOWrlqbZJpukCHLB-1Ag067gTWupZtiQ";

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
                                    "postalCode", "M34 1AA")));

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

    String ADDRESS_JSON_1 =
            "{\"buildingNumber\":10,\"streetName\":\"DowningStreet\",\"dependentAddressLocality\":\"Westminster\",\"addressLocality\":\"London\",\"postalCode\":\"SW1A2AA\",\"addressCountry\":\"GB\",\"validFrom\":\"2019-07-24\"}";
    String ADDRESS_JSON_2 =
            "{\"buildingNumber\":11,\"streetName\":\"DowningStreet\",\"dependentAddressLocality\":\"Westminster\",\"addressLocality\":\"London\",\"postalCode\":\"SW1A2AA\",\"addressCountry\":\"GB\",\"validFrom\":\"2019-07-24\"}";

    String SIGNED_JWT =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJBdWRpZW5jZSIsInN1YiI6InRlc3RDbGllbnRJZCIsIm5iZiI6MTY1MTY3MzQ3NCwic2hhcmVkX2NsYWltcyI6eyJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6bnVsbCwib3JnYW5pemF0aW9uTmFtZSI6bnVsbCwic3RyZWV0QWRkcmVzcyI6bnVsbCwicG9zdGFsQ29kZSI6bnVsbCwiYWRkcmVzc0xvY2FsaXR5IjpudWxsLCJ0eXBlIjpudWxsLCJhZGRyZXNzUmVnaW9uIjpudWxsfV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidmFsaWRVbnRpbCI6bnVsbCwidmFsaWRGcm9tIjpudWxsLCJ0eXBlIjoiZmlyc3RfbmFtZSIsInZhbHVlIjoiRGFuIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIyMDExLTAxLTAxIn1dfSwiaXNzIjoidGVzdENsaWVudElkIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJyZWRpcmVjdF91cmkiOiJjYWxsYmFja1VyaT9pZD1jcmlfaWQiLCJzdGF0ZSI6InJlYWQiLCJleHAiOjE2NTE2NzQzNzQsImlhdCI6MTY1MTY3MzQ3NCwiY2xpZW50X2lkIjoidGVzdENsaWVudElkIn0.jfYDzFJjANSkwC7Zxd45aJBzv8dgXNRdi3oWvFUEg3aWWfXW6a-R29CDrCZZXNueoOEQFjkz88R5Az0urnohgw";
}
