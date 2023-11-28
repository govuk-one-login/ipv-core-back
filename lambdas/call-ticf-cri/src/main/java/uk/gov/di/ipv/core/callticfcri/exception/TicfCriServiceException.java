package uk.gov.di.ipv.core.callticfcri.exception;

public class TicfCriServiceException extends Exception {
    public TicfCriServiceException(String message) {
        super(message);
    }

    public TicfCriServiceException(Throwable cause) {
        super(cause);
    }
}
