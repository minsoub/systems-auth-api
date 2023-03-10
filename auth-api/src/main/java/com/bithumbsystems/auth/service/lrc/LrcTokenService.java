package com.bithumbsystems.auth.service.lrc;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_TOKEN;
import static com.bithumbsystems.auth.core.util.JwtGenerateUtil.generateOtp;

import com.bithumbsystems.auth.api.config.constant.SecurityConstant;
import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.request.token.TokenGenerateRequest;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.core.util.JwtGenerateUtil;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.authentication.entity.LrcAccount;
import com.bithumbsystems.auth.data.redis.AuthRedisService;
import com.bithumbsystems.auth.service.TokenService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
@Slf4j
@Service
@RequiredArgsConstructor
public class LrcTokenService implements TokenService {

  private final JwtProperties jwtProperties;
  private final AuthRedisService authRedisService;

  /**
   * refresh 토큰으로 갱신
   *
   * @param authRequest the auth request
   * @return mono
   */
  public Mono<TokenResponse> reGenerateToken(Mono<AuthRequest> authRequest) {
    return authRequest.flatMap(tokenInfo -> {
      log.debug("reGenerateToken data => {}", authRequest);

      return JwtVerifyUtil.check(tokenInfo.getRefreshToken(), jwtProperties.getSecret())
              .flatMap(verificationResult -> authRedisService.getToken(
                              verificationResult.claims.get("iss") + "::LRC")
                      .filter(token -> token.equals(tokenInfo.getAccessToken()))
                      .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_TOKEN)))
                      .then(generateToken(TokenGenerateRequest.builder()
                              .accountId(verificationResult.claims.get("account_id").toString())
                              .roles(verificationResult.claims.get("ROLE"))
                              .siteId(verificationResult.claims.get("sub").toString())
                              .claims(Map.of("ROLE", "USER", "account_id", verificationResult.claims.get("account_id").toString()))
                              .email(verificationResult.claims.getIssuer())
                              .build())
                      ));
    });
  }


  public Mono<TokenResponse> generateToken(TokenGenerateRequest request) {
    log.debug("generateToken create......{}", request);

    GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
            .builder()
            .secret(jwtProperties.getSecret())
            .expiration(jwtProperties.getAccessExpiration())
            .refreshExpiration(jwtProperties.getRefreshExpiration())
            .subject(request.getSiteId())
            .issuer(request.getEmail())
            .claims(request.getClaims())
            .build();
    var tokenInfo = JwtGenerateUtil.generate(generateTokenInfo)
            .toBuilder()
            .build();

    var tokenResponse = TokenResponse.builder()
            .id(request.getAccountId())
            .accessToken(tokenInfo.getAccessToken())
            .accessExpiresAt(tokenInfo.getExpiresAt())
            .refreshToken(tokenInfo.getRefreshToken())
            .refreshExpiresAt(tokenInfo.getRefreshExpiresAt())
            .issuedAt(tokenInfo.getIssuedAt())
            .email(request.getEmail())
            .build();

    log.debug("tokenResponse info => {}", tokenResponse);
    return authRedisService.saveToken(request.getEmail() + "::LRC", tokenInfo.getAccessToken())
            .map(result -> tokenResponse);
  }

  /**
   * 1차 토큰 생성
   *
   * @param account   the account
   * @param tokenType the token type
   * @return mono mono
   */
  public Mono<TokenOtpInfo> generateTokenOne(LrcAccount account, String decryptEmail, TokenType tokenType) {
    log.debug("generateTokenOne create......{} {}", account.getId(), tokenType);
    GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
            .builder()
            .secret(jwtProperties.getSecret())
            .expiration(jwtProperties.getAccessExpiration())
            .subject(SecurityConstant.LRC_SITE_ID)
            .issuer(decryptEmail)
            .claims(Map.of("ROLE", "USER", "account_id", account.getId()))
            .build();

    TokenOtpInfo tokenInfo = generateOtp(generateTokenInfo).toBuilder().siteId(SecurityConstant.LRC_SITE_ID).build();
    log.debug("siteId:{}", SecurityConstant.LRC_SITE_ID);
    return authRedisService.saveToken(account.getEmail() + "::LRC", tokenInfo.toString())
            .map(result -> tokenInfo);
  }
}

