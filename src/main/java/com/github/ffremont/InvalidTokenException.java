package com.github.ffremont;

public class InvalidTokenException extends Exception{
    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
