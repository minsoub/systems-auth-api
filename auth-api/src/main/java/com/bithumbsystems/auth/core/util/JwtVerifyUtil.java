package com.bithumbsystems.auth.core.util;

import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.VerificationResult;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * The type Jwt verify util.
 */
@Slf4j
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

        log.debug("expiration check...");
        if (expiration.before(new Date())) {
            log.debug("Token validation check error : EXPIRED_TOKEN");
            log.debug("Token get date : {}", expiration);
            throw new UnauthorizedException(ErrorCode.EXPIRED_TOKEN);
        }

        log.debug("return verificationResult");
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
        var apiKeySecretBytes = secret.getBytes();
        var signatureAlgorithm = SignatureAlgorithm.HS256;
        var signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        log.debug("Jwts parseBuild...");
        Claims claims;
        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        }catch(Exception ex) {
            log.error(ex.getMessage());
            throw new UnauthorizedException(ErrorCode.EXPIRED_TOKEN);
        }

        return claims;
    }
}

