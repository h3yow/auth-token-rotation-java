package com.github.h3yow.authtokenrotationjava.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Buffers auth API request bodies so the refresh credential inside the body
 * can be read by the rate-limit interceptor and again by the controller. Only
 * JSON bodies on the auth surface are wrapped; everything else streams
 * untouched.
 */
@Component
@Order(1)
public class CachedBodyFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (shouldBuffer(request)) {
            byte[] body = request.getInputStream().readAllBytes();
            filterChain.doFilter(new CachedBodyHttpServletRequest(request, body), response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private boolean shouldBuffer(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contentType = request.getContentType();
        return uri != null && uri.startsWith("/api/auth/")
                && contentType != null
                && contentType.toLowerCase().startsWith(MediaType.APPLICATION_JSON_VALUE);
    }
}
