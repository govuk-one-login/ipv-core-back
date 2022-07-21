package uk.gov.di.ipv.core.statemachine;

public interface Event {

    //State resolve();
    StateMachineResult resolve(Context context);

}
