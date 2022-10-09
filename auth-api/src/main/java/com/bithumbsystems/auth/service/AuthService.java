package com.bithumbsystems.auth.service;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.AUTHORIZATION_FAIL;

import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.DuplicatedLoginException;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.VerificationResult;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.authentication.entity.RsaCipherInfo;
import com.bithumbsystems.auth.data.authentication.service.RoleManagementDomainService;
import com.bithumbsystems.auth.data.authentication.service.RsaCipherInfoDomainService;
import com.bithumbsystems.auth.data.authorization.service.AuthorizationService;
import com.bithumbsystems.auth.data.redis.AuthRedisService;
import com.bithumbsystems.auth.service.cipher.RsaCipherService;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.AntPathMatcher;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * The type Auth service.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

  private final JwtProperties jwtProperties;

  private final AuthRedisService authRedisService;

  private final RsaCipherInfoDomainService rsaCipherInfoDomainService;

  private final RsaCipherService rsaCipherService;
  private final AuthorizationService authorizationService;

  private final RoleManagementDomainService roleManagementDomainService;

  private static final String RSA_CIPHER_KEY = "rsa-cipher-key";
  private static final Map<String, String> PASS_PATH = Map.of(
      "/adm/token", "PUT",
      "/api/v1/authorize", "POST",
      "/api/v1/role/{roleManagementId}", "GET",
      "/api/v1/role/{roleManagementId}/sites/{siteId}", "GET",
      "/api/v1/account", "GET");

  private static final List<String> AUTH_INIT_PATH = List.of(
      "/api/v1/auth/mapping/init",
      "/api/v1/auth/mapping",
      "/api/v1/menu/mapping",
      "/api/v1/menu/mapping/init");

  private static final List<String> AUTH_INIT_ROLE = List.of(
      "SUPER_ADMIN",
      "SUPER-ADMIN");

  /**
   * Authorize
   *
   * @param tokenRequest the token request
   * @return the mono
   */
  public Mono<String> authorize(Mono<TokenValidationRequest> tokenRequest) {
    return tokenRequest
        .flatMap(this::tokenValidate)
        .flatMap(verificationResult -> checkAvailableResource(verificationResult)
            .flatMap(isAccess -> {
              if (Boolean.FALSE.equals(isAccess)) {
                return Mono.error(new UnauthorizedException(AUTHORIZATION_FAIL));
              }
              return Mono.just(verificationResult);
            }))
        .flatMap(verificationResult -> {
          var key = verificationResult.claims.getIssuer();
          if (verificationResult.claims.get("ROLE").equals("USER")) {
            key += "::LRC";
          }

          return authRedisService.getToken(key)
              .filter(token -> token.equals(verificationResult.token))
              .map(token -> ResultCode.SUCCESS.name())
              .switchIfEmpty(
                  Mono.error(new DuplicatedLoginException(ErrorCode.USER_ALREADY_LOGIN)));
        });
  }

  private Mono<Boolean> checkAvailableResource(VerificationResult verificationResult) {
    AntPathMatcher pathMatcher = new AntPathMatcher();
    final var roles = verificationResult.claims.get("ROLE");

    var isPass = PASS_PATH.entrySet().stream()
        .anyMatch(pass -> pathMatcher.match(pass.getKey(), verificationResult.requestUri)
            && pass.getValue().equals(verificationResult.method)
        );

    if (isPass || roles.equals("USER") || (AUTH_INIT_ROLE.contains(verificationResult.activeRole)
        && AUTH_INIT_PATH.contains(verificationResult.requestUri))
    ) {
      return Mono.just(true);
    }

    return Mono.just(roles)
        .flatMap(role -> authRedisService.getRoleAuthorization(verificationResult.activeRole)
            .switchIfEmpty(extractProgram(verificationResult.activeRole))
            .flatMap(programString -> {
              var hasResource = hasResource(programString, verificationResult.requestUri,
                  verificationResult.method);
              return Mono.just(hasResource);
            })
        ).switchIfEmpty(Mono.just(true));
  }

  private Mono<String> extractProgram(String roleManagementId) {
    return authorizationService.findRolePrograms(roleManagementId)
        .flatMap(program -> Mono.just(program.getActionMethod() + "|" + program.getActionUrl()))
        .collectList()
        .publishOn(Schedulers.boundedElastic())
        .map(programString -> {
          log.info("roleManagementId: " + roleManagementId);
          log.info("programString: " + programString.toString());

          authRedisService.saveAuthorization(roleManagementId, programString.toString())
              .subscribe();
          return programString.toString();
        });
  }

  private boolean hasResource(String programString, String requestUri, String requestMethod) {
    return Arrays.stream(programString.split(","))
        .anyMatch(program -> {
          final var api = program.split("\\|");
          final var method = api[0].replaceAll("\\[|\\]", "");
          final var uri = api[1].replaceAll("\\[|\\]", "");
          AntPathMatcher pathMatcher = new AntPathMatcher();
          return method.trim().equals(requestMethod.trim())
              && pathMatcher.match(uri.trim(), requestUri.trim());
        });
  }

  /**
   * Token Validation 을 체크한다.
   *
   * @param tokenValidationRequest the token validation request
   * @return mono mono
   */
  private Mono<VerificationResult> tokenValidate(TokenValidationRequest tokenValidationRequest) {
    return JwtVerifyUtil.check(tokenValidationRequest.getToken(), jwtProperties.getSecret(),
        tokenValidationRequest.getRequestUri(), tokenValidationRequest.getMethod().name(),
        tokenValidationRequest.getActiveRole());
  }

  @Transactional
  public Mono<RsaCipherInfo> createRsaCipherCache() {
    Map<String, String> serverRsaKeys = rsaCipherService.getRsaKeys();
    log.debug("serverRsaKeys : {}", serverRsaKeys);

    return rsaCipherInfoDomainService.save(RsaCipherInfo.builder()
        .id(RSA_CIPHER_KEY)
        .serverPrivateKey(serverRsaKeys.get(rsaCipherService.PRIVATE_KEY_NAME))
        .serverPublicKey(serverRsaKeys.get(rsaCipherService.PUBLIC_KEY_NAME))
        .createdAt(LocalDateTime.now())
        .build());
  }

  public Mono<String> getRsaPublicKey() {
    return rsaCipherInfoDomainService.findById(RSA_CIPHER_KEY)
        .map(RsaCipherInfo::getServerPublicKey);
  }

  public Mono<String> getRsaPrivateKey() {
    return rsaCipherInfoDomainService.findById(RSA_CIPHER_KEY)
        .map(RsaCipherInfo::getServerPrivateKey);
  }

  public Disposable redisInit() {
    return roleManagementDomainService.findAll()
        .publishOn(Schedulers.boundedElastic())
        .doOnNext(roleManagement -> {
          authRedisService.delete(roleManagement.getId()).subscribe();
          authRedisService.delete("ROLE_" + roleManagement.getId()).subscribe();
        }).subscribe();
  }
}
