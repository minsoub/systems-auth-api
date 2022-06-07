package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.request.ClientRegisterRequest;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.core.model.request.UserJoinRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.service.AccountService;
import com.bithumbsystems.auth.service.AuthService;
import com.bithumbsystems.auth.service.OtpService;
import com.bithumbsystems.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Log4j2
@Component
@RequiredArgsConstructor
public class AuthHandler {

    private final AuthService authService;
    private final AccountService accountService;
    private final UserService userService;
    private final OtpService otpService;


    public Mono<ServerResponse> registerClient(ServerRequest request) {
        Mono<ClientRegisterRequest> clientRegisterRequestMono = request.bodyToMono(ClientRegisterRequest.class);
        return ServerResponse.ok().body(authService.registerClient(clientRegisterRequestMono), TokenResponse.class);
    }

    public Mono<ServerResponse> generateToken(ServerRequest request) {
        Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(authService.generateToken(authRequest), TokenResponse.class);
    }

    public Mono<ServerResponse> refreshToken(ServerRequest request) {
        Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(null, TokenInfo.class);
    }

    public Mono<ServerResponse> deleteToken(ServerRequest request) {
        Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(null, TokenInfo.class);
    }

    /**
     * 사용자 로그인 처리 (운영자)
     * 사용자 로그인 후 OTP 처리를 해야 한다.
     *
     * @param request
     * @return
     */
    public Mono<ServerResponse> login(ServerRequest request) {
        log.debug("login called..");
        Mono userRequest = request.bodyToMono(UserRequest.class);

        return ServerResponse.ok().body(accountService.login(userRequest), TokenOtpInfo.class);

        //return ServerResponse.ok().body(accountService.login(authRequest), TokenInfo.class);
    }

    /**
     * QR 바코드를 생성해서 리턴한다.
     *
     * @param request
     * @return
     */
    public Mono<ServerResponse> otp(ServerRequest request) {
        Mono otpRequest = request.bodyToMono(OtpRequest.class);

        return ServerResponse.ok().body(accountService.otp(otpRequest), TokenInfo.class);  // BodyInserters.fromValue(otpRequest));

    }


    /**
     * 일반 사용자 로그인 인증 처리
     *
     * @param request
     * @return
     */
    public Mono<ServerResponse> userLogin(ServerRequest request) {
        Mono userRequest = request.bodyToMono(UserRequest.class);

        return ServerResponse.ok().body(userService.userLogin(userRequest), TokenInfo.class);
    }


    /**
     * QR 바코드를 생성해서 리턴한다. (사용자)
     *
     * @param request
     * @return
     */
    public Mono<ServerResponse> userOtp(ServerRequest request) {
        Mono otpRequest = request.bodyToMono(OtpRequest.class);

        return ServerResponse.ok().body(userService.userOtp(otpRequest), TokenInfo.class);  // BodyInserters.fromValue(otpRequest));

    }

    /**
     * Token Validation을 체크한다.
     *
     * @param request
     * @return
     */
    public Mono<ServerResponse> tokenValidate(ServerRequest request) {

        Mono tokenRequest = request.bodyToMono(TokenValidationRequest.class);

        return ServerResponse.ok().body(authService.tokenValidate(tokenRequest), String.class);
    }

    /**
     * 사용자 가입을 처리한다.
     *
     * @param request
     * @return
     */
    public Mono<ServerResponse> userJoin(ServerRequest request) {
        Mono joinRequest = request.bodyToMono(UserJoinRequest.class);

        return ServerResponse.ok().body(userService.join(joinRequest), SingleResponse.class);
    }
}
