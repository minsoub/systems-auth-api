package com.bithumbsystems.auth.service.admin;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_TOKEN;
import static com.bithumbsystems.auth.core.util.JwtGenerateUtil.generateOtp;

import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.request.token.TokenGenerateRequest;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.core.util.JwtGenerateUtil;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import com.bithumbsystems.auth.data.mongodb.client.entity.RoleManagement;
import com.bithumbsystems.auth.data.mongodb.client.service.AdminAccessDomainService;
import com.bithumbsystems.auth.data.mongodb.client.service.RoleManagementDomainService;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import com.bithumbsystems.auth.service.TokenService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * The type Token service.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminTokenService implements TokenService {

  private final JwtProperties jwtProperties;

  private final RedisTemplateSample redisTemplateSample;
  private final AdminAccessDomainService adminAccessDomainService;

  private final RoleManagementDomainService roleManagementDomainService;


  /**
   * 1차 토큰 생성
   *
   * @param account   the account
   * @param tokenType the token type
   * @return mono mono
   */
  public Mono<TokenOtpInfo> generateTokenOne(AdminAccount account, TokenType tokenType) {

    log.debug("generateTokenOne create......{} {}", account.getId(), tokenType);
    return adminAccessDomainService.findByAdminId(account.getId())
        .flatMap(result -> {
          log.debug("admin_access data => {}", result);
          return roleManagementDomainService.findFirstRole(result.getRoles())
              .flatMap(roleManagement -> roleManagementDomainService.findByRoleInIds(result.getRoles())
                  .map(RoleManagement::getId)
                  .collectList()
                  .flatMap(roles -> {
                        GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
                            .builder()
                            .secret(jwtProperties.getSecret())
                            .expiration(jwtProperties.getAccessExpiration())
                            .subject(roleManagement.getSiteId())
                            .issuer(account.getEmail())
                            .claims(
                                Map.of("ROLE", roles, "account_id", account.getId()))  // 지금은 인증
                            .build();

                        return Mono.just(generateOtp(generateTokenInfo)
                            .toBuilder()
                            .siteId(roleManagement.getSiteId())
                            .build());
                      }
                  )).publishOn(Schedulers.boundedElastic()).doOnNext(tokenOtpInfo ->
                  redisTemplateSample.saveToken(account.getEmail() + "::OTP",
                          tokenOtpInfo.toString())
                      .log("result ->save success..")
                      .subscribe()).flatMap(Mono::just);
        })
        .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_TOKEN)));
  }


  /**
   * 2차 인증에 대한 토큰 생성 및 저장
   *
   * @param request the request
   * @return mono
   */
  public Mono<TokenInfo> generateToken(TokenGenerateRequest request) {
    log.debug("generateToken create......{}", request);

    log.debug("admin_access data => {}", request);

    GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
        .builder()
        .secret(jwtProperties.getSecret())
        .expiration(jwtProperties.getAccessExpiration())
        .refreshExpiration(jwtProperties.getRefreshExpiration())
        .subject(request.getSiteId())
        .issuer(request.getEmail())
        .claims(
            Map.of("ROLE", request.getRoles(), "account_id", request.getAccountId(), "user_id",
                request.getEmail())) // 운영자에 대한 Role이 필요.
        .build();
    var tokenInfo = JwtGenerateUtil.generate(generateTokenInfo)
        .toBuilder()
        .build();
    tokenInfo.setStatus(request.getStatus());
    log.debug("token info => {}", tokenInfo);
    return redisTemplateSample.saveToken(request.getEmail(), tokenInfo.getAccessToken())
        .publishOn(Schedulers.boundedElastic())
        .map(result -> {
          redisTemplateSample.deleteToken(request.getEmail() + "::OTP").log("delete otp token")
              .subscribe();
          return tokenInfo;
        });
  }

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
          .flatMap(verificationResult -> redisTemplateSample.getToken(
                  (String) verificationResult.claims.get("iss"))
              .filter(token -> token.equals(tokenInfo.getAccessToken()))
              .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_TOKEN)))
              .then(generateTokenRefresh(TokenGenerateRequest.builder()
                  .accountId(verificationResult.claims.get("account_id").toString())
                  .roles(verificationResult.claims.get("ROLE"))
                  .siteId(verificationResult.claims.get("sub").toString())
                  .email(verificationResult.claims.getIssuer())
                  .claims(Map.of("ROLE", verificationResult.claims.get("ROLE"),
                      "account_id", verificationResult.claims.get("account_id").toString(),
                      "user_id", verificationResult.claims.getIssuer())) // 운영자에 대한 Role이 필요.
                  .build())
              ));
    });
  }


  private Mono<TokenResponse> generateTokenRefresh(TokenGenerateRequest request) {
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
        .accessToken(tokenInfo.getAccessToken())
        .refreshToken(tokenInfo.getRefreshToken())
        .issuedAt(tokenInfo.getIssuedAt())
        .email(request.getEmail())
        .build();

    log.debug("token info => {}", tokenInfo);
    return redisTemplateSample.saveToken(request.getEmail(), tokenInfo.getAccessToken())
        .map(result -> tokenResponse);
  }


}
