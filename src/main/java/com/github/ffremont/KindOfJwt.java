package com.github.ffremont;

public interface KindOfJwt {
    String generate(MetaToken meta);
    public MetaToken verify(String token, String issuer) throws InvalidTokenException;
}
