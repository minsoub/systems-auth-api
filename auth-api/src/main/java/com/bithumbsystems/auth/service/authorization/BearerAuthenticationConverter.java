package com.bithumbsystems.auth.service.authorization;

import static com.bithumbsystems.auth.api.config.constant.SecurityConstant.ISOLATE_BEARER_VALUE;
import static com.bithumbsystems.auth.api.config.constant.SecurityConstant.MATCH_BEARER_LENGTH;
import static com.bithumbsystems.auth.core.util.JwtVerifyUtil.check;

import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.core.model.auth.UserPrincipal;
import com.bithumbsystems.auth.core.model.auth.VerificationResult;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class BearerAuthenticationConverter implements ServerAuthenticationConverter {

  private final JwtProperties jwtProperties;

  @Override
  public Mono<Authentication> convert(ServerWebExchange exchange) {
    return Mono.justOrEmpty(exchange)
        .flatMap(BearerAuthenticationConverter::extract)
        .filter(MATCH_BEARER_LENGTH)
        .flatMap(ISOLATE_BEARER_VALUE)
        .flatMap(token -> check(token, jwtProperties.getSecret()))
        .flatMap(BearerAuthenticationConverter::create);
  }

  public static Mono<String> extract(ServerWebExchange serverWebExchange) {
    return Mono.justOrEmpty(serverWebExchange.getRequest()
        .getHeaders()
        .getFirst(HttpHeaders.AUTHORIZATION));
  }

  public static Mono<Authentication> create(VerificationResult verificationResult) {
    var claims = verificationResult.claims;
    var subject = claims.getSubject();
    var principal = new UserPrincipal(subject, claims.getIssuer());

    if (claims.get("ROLE") instanceof java.lang.String) {
      return Mono.justOrEmpty(
          new UsernamePasswordAuthenticationToken(principal, null, List.of(new SimpleGrantedAuthority((String)claims.get("ROLE")))));
    } else {
      List<String> roles = claims.get("ROLE", List.class);
      var authorities = roles.stream().map(SimpleGrantedAuthority::new)
          .collect(Collectors.toList());
      return Mono.justOrEmpty(
          new UsernamePasswordAuthenticationToken(principal, null, authorities));
    }
  }
}
