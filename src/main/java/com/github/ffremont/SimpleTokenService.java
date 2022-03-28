package com.github.ffremont;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneId;


/**
 * JWT basé sur HMAC256
 */
class SimpleTokenService implements KindOfJwt {

    private byte[] secret;

    public SimpleTokenService(byte[] secret) {
        this.secret = secret;
    }

    public String generate(MetaToken meta) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTCreator.Builder builder = JWT.create()
                .withIssuer(meta.issuer())
                .withSubject(meta.subject())
                .withNotBefore(Date.from(meta.notBefore().atZone(ZoneId.systemDefault()).toInstant()))
                .withExpiresAt(Date.from(meta.expireAt().atZone(ZoneId.systemDefault()).toInstant()));

        meta.audiences().stream().forEach(builder::withAudience);

        return builder.sign(algorithm);
    }

    @Override
    public MetaToken verify(String token, String issuer) throws InvalidTokenException {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer).build();
        try {
            DecodedJWT jwt = verifier.verify(token);

            return new MetaToken(jwt.getIssuer(), jwt.getSubject(), jwt.getAudience(), LocalDateTime.ofInstant(jwt.getExpiresAt().toInstant(), ZoneId.systemDefault()), LocalDateTime.ofInstant(jwt.getNotBefore().toInstant(), ZoneId.systemDefault()));
        }catch(JWTVerificationException e){
            throw new InvalidTokenException("Jeton invalide",e);
        }
    }


}
