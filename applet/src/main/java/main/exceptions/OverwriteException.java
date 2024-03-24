package main.exceptions;

public class OverwriteException extends CardRuntimeException {
    public OverwriteException(String message) {
        super(message);
    }
}
