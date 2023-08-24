package uk.gov.di.ipv.core.library.domain.cimitvc;

import lombok.Getter;

@Getter
public class CiMitJwt {
    private String sub;
    private String iss;
    private Long nbf;
    private Long exp;
    private CiMitVc vc;
}
