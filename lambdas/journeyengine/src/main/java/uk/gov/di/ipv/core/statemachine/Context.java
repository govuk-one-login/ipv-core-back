package uk.gov.di.ipv.core.statemachine;

public class Context {

    private static Context EMPTY_CONTEXT;

    {
        this.EMPTY_CONTEXT = new Context();
    }

     public static Context emptyContext(){
        return EMPTY_CONTEXT;
    }


}
