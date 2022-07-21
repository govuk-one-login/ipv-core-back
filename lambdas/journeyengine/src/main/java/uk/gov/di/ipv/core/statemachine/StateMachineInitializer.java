package uk.gov.di.ipv.core.statemachine;

import java.util.HashMap;
import java.util.Map;

public class StateMachineInitializer {

    private Map<String, State> states = new HashMap<>();

    public Map<String, State> initialize(){

        var INIT = new State("INIT");
        states.put(INIT.getName(), INIT);
        var CRI_SUPER = new State("CRI_SUPER");
        states.put(CRI_SUPER.getName(), CRI_SUPER);
        var PAGE_IPV_START = new State("PAGE-IPV-START");
        states.put(PAGE_IPV_START.getName(), PAGE_IPV_START);
        var CRI_UK_PASSPORT = new State("CRI-UK-PASSPORT").withParent(CRI_SUPER);
        var CRI_ADDRESS = new State("CRI-ADDRESS").withParent(CRI_SUPER);
        var CRI_FRAUD = new State("CRI-FRAUD").withParent(CRI_SUPER);
        var CRI_KBV = new State("CRI-KBV").withParent(CRI_SUPER);
        var PAGE_KBV_TRANSITION = new State("PAGE-KBV-TRANSITION");
        var PAGE_SUCCESS = new State("PAGE-SUCCESS");
        var SESSION_END = new State("SESSION_END");
        var PAGE_IDENTITY_FAIL = new State("PAGE-IDENTITY-FAIL");
        var PAGE_KBV_FAIL = new State("PAGE-KBV-FAIL");
        var CRI_ERROR = new State("ERROR_CRI");


        CRI_SUPER.withEvent(new BasicEvent("error", CRI_ERROR, new PageResponse("pyi-error")));

        INIT.withEvent(new BasicEvent("next", PAGE_IPV_START, new PageResponse("ipv-start")));
        PAGE_IPV_START.withEvent(new BasicEvent("next", CRI_UK_PASSPORT, new CriResponse("cri/start/uk-passport")));
        CRI_ADDRESS.withEvent(new BasicEvent("next", CRI_ADDRESS, new CriResponse("cri/start/address")));
        CRI_FRAUD.withEvent(new BasicEvent("next", PAGE_KBV_TRANSITION, new PageResponse("kbv-transition")));
        PAGE_KBV_TRANSITION.withEvent(new BasicEvent("next", CRI_KBV, new CriResponse("cri/start/kbv")));
        CRI_KBV.withEvent(new BasicEvent("next", CRI_KBV, new CriResponse("cri/start/kbv")));
        PAGE_SUCCESS.withEvent(new BasicEvent("next", SESSION_END, new JourneyResponse("session/end")));

        return states;
    }

}
