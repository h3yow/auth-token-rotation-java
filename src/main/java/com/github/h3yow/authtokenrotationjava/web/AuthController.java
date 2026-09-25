package com.github.h3yow.authtokenrotationjava.web;

import com.github.h3yow.authtokenrotationjava.domain.TokenPair;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import com.github.h3yow.authtokenrotationjava.web.dto.LoginRequest;
import com.github.h3yow.authtokenrotationjava.web.dto.MessageResponse;
import com.github.h3yow.authtokenrotationjava.web.dto.TokenResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 登录签发、刷新轮换、注销撤销接口。
 *
 * <p>调用方身份通过 {@code X-Client-Id} 声明，并由服务端与令牌/链路绑定关系
 * 做一致性校验；刷新与注销令牌通过 {@code Authorization: Bearer <token>} 传递。</p>
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestHeader("X-Client-Id") String clientId,
                               @RequestBody LoginRequest request) {
        TokenPair pair = authService.issue(clientId, request.username(), request.password());
        return toResponse(pair);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestHeader("X-Client-Id") String clientId,
                                 @RequestHeader("Authorization") String authorization) {
        TokenPair pair = authService.rotate(clientId, stripBearer(authorization));
        return toResponse(pair);
    }

    @PostMapping("/logout")
    public MessageResponse logout(@RequestHeader("X-Client-Id") String clientId,
                                  @RequestHeader("Authorization") String authorization) {
        authService.logout(clientId, stripBearer(authorization));
        return new MessageResponse("会话已注销，该会话所有访问令牌立即失效");
    }

    private TokenResponse toResponse(TokenPair pair) {
        return new TokenResponse(pair.accessToken(), pair.refreshToken(), pair.sessionId(),
                pair.accessTokenExpiresAt(), pair.refreshTokenExpiresAt());
    }

    private static String stripBearer(String authorization) {
        if (authorization == null || authorization.isBlank()) {
            return null;
        }
        String trimmed = authorization.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return trimmed.substring(7).trim();
        }
        // 允许直接传入原始令牌，交由服务层做格式校验
        return trimmed;
    }
}
