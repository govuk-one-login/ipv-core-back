package uk.gov.di.ipv.core.library.exceptions;

public class CriOAuthSessionNotFoundException extends Exception {
    public CriOAuthSessionNotFoundException() {
        super("CRI OAuth session not found");
    }
}
