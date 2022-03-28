package com.github.ffremont;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * JWT basé sur ECDSA
 *
 * @see //stackoverflow.com/questions/37722090/java-jwt-with-public-private-keys
 *
 */
public class SafeTokenService implements KindOfJwt{

    /**
     * la clef privée
     */
    private PrivateKey privateKey;
    /**
     * la clef publique
     */
    private PublicKey publicKey;

    public SafeTokenService(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Permet de générer un couple de clefs ECDSA
     *
     * @return
     * @throws Exception
     */
    public static Keys generateRSAKeys() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        g.initialize(spec);
        KeyPair keyPair = g.generateKeyPair();
        return new Keys(keyPair.getPrivate(), keyPair.getPublic());
    }

    public MetaToken verify(String token, String issuer) throws InvalidTokenException {
        Algorithm algorithm = Algorithm.ECDSA256((ECPublicKey) publicKey, null);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        try {
            DecodedJWT jwt = verifier.verify(token);

            return new MetaToken(jwt.getIssuer(), jwt.getSubject(), jwt.getAudience(), LocalDateTime.ofInstant(jwt.getExpiresAt().toInstant(), ZoneId.systemDefault()), LocalDateTime.ofInstant(jwt.getNotBefore().toInstant(), ZoneId.systemDefault()));
        }catch(JWTVerificationException e){
            throw new InvalidTokenException("Jeton invalide",e);
        }
    }

    @Override
    public String generate(MetaToken meta) {
        try {
            Algorithm algorithm = Algorithm.ECDSA256(null, (ECPrivateKey) privateKey);
            JWTCreator.Builder builder = JWT.create()
                    .withIssuer(meta.issuer())
                    .withSubject(meta.subject())
                    .withNotBefore(Date.from(meta.notBefore().atZone(ZoneId.systemDefault()).toInstant()))
                    .withExpiresAt(Date.from(meta.expireAt().atZone(ZoneId.systemDefault()).toInstant()));

            meta.audiences().stream().forEach(builder::withAudience);

            return builder.sign(algorithm);
        } catch (JWTCreationException x) {
            throw new RuntimeException("Oups erreur dans la génération ECDSA du jeton", x);
        }
    }

    public record Keys(PrivateKey privateKey, PublicKey publicKey){}
}
