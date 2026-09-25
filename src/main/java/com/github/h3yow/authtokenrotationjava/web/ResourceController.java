package com.github.h3yow.authtokenrotationjava.web;

import com.github.h3yow.authtokenrotationjava.security.AccessTokenAuthenticationFilter;
import com.github.h3yow.authtokenrotationjava.service.AuthService;
import com.github.h3yow.authtokenrotationjava.web.dto.MessageResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 需要携带有效访问令牌的受保护资源接口。
 * 能到达这里的请求已经过"鉴权 → 限流"两个过滤器。
 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/ping")
    public MessageResponse ping(HttpServletRequest request) {
        AuthService.AuthenticatedCaller caller = (AuthService.AuthenticatedCaller)
                request.getAttribute(AccessTokenAuthenticationFilter.CALLER_ATTRIBUTE);
        return new MessageResponse("pong: user=" + caller.username()
                + ", client=" + caller.clientId()
                + ", session=" + caller.sessionId());
    }
}
