package com.bithumbsystems.auth.core.util;

import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.VerificationResult;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.log4j.Log4j2;
import reactor.core.publisher.Mono;

/**
 * The type Jwt verify util.
 */
@Log4j2
public final class JwtVerifyUtil {

    /**
     * Token Validation check
     *
     * @param token  the token
     * @param secret the secret
     * @return mono
     */
    public static Mono<VerificationResult> check(String token, String secret) {
        log.debug("jwt verify check called.. {}, {}", secret, token);
        return Mono.just(verify(token, secret))
            .onErrorResume(e -> Mono.error(new UnauthorizedException(ErrorCode.INVALID_TOKEN)));
    }

    private static VerificationResult verify(String token, String secret) {
        log.debug("VerificationResult called.. {}, {}", secret, token);
        var claims = getAllClaimsFromToken(token, secret);
        final Date expiration = claims.getExpiration();

        if (expiration.before(new Date()))
            throw new UnauthorizedException(ErrorCode.EXPIRED_TOKEN);

        return new VerificationResult(claims, token);
    }

    /**
     * Gets all claims from token.
     *
     * @param token  the token
     * @param secret the secret
     * @return the all claims from token
     * @throws UnauthorizedException the unauthorized exception
     */
    public static Claims getAllClaimsFromToken(String token, String secret) throws UnauthorizedException {
        log.debug("getAllClaimsFromToken called.. {}, {}", secret, token);
        var apiKeySecretBytes = secret.getBytes();  // DatatypeConverter.parseBase64Binary(secret);
        var signatureAlgorithm = SignatureAlgorithm.HS256;
        var signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        log.debug("Jwts parseBuild...");
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}

