package com.github.h3yow.authtokenrotationjava.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 集成测试 HTTP 客户端：每个请求都打印调用方标识、令牌状态与判定依据，
 * 便于并发刷新/重放/限流场景下稳定复现与解释结论。
 */
public class HttpTestClient {

    private static final Logger log = LoggerFactory.getLogger("TEST");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final String baseUrl;

    public HttpTestClient(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public Result login(String clientId, String username, String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username);
        body.put("password", password);
        Result result = exchange("POST", "/auth/login", clientId, null, toJson(body));
        log.info("[TEST 请求] 场景=登录 | clientId={} | username={} | token状态=无 -> HTTP {} error={} reason={}",
                clientId, username, result.status(), result.errorCode(), result.reason());
        return result;
    }

    public Result refresh(String clientId, String refreshToken) {
        Result result = exchange("POST", "/auth/refresh", clientId, refreshToken, null);
        log.info("[TEST 请求] 场景=刷新 | clientId={} | refreshToken={} | token状态={} -> HTTP {} error={} reason={}",
                clientId, mask(refreshToken), tokenStateDescription(result),
                result.status(), result.errorCode(), result.reason());
        return result;
    }

    public Result logout(String clientId, String accessToken) {
        Result result = exchange("POST", "/auth/logout", clientId, accessToken, null);
        log.info("[TEST 请求] 场景=注销 | clientId={} | accessToken={} | token状态={} -> HTTP {} error={} reason={}",
                clientId, mask(accessToken), tokenStateDescription(result),
                result.status(), result.errorCode(), result.reason());
        return result;
    }

    public Result ping(String clientIdHeader, String accessToken) {
        Result result = exchange("GET", "/api/ping", clientIdHeader, accessToken, null);
        log.info("[TEST 请求] 场景=受保护访问 | headerClientId={} | accessToken={} | token状态={} -> HTTP {} error={} reason={}",
                clientIdHeader, mask(accessToken), tokenStateDescription(result),
                result.status(), result.errorCode(), result.reason());
        return result;
    }

    public Result pingWithAnyHeader(String clientIdHeader, String accessToken) {
        return ping(clientIdHeader, accessToken);
    }

    public Result exchange(String method, String path, String clientId,
                             String bearerToken, String jsonBody) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .timeout(Duration.ofSeconds(10));
            if (clientId != null) {
                builder.header("X-Client-Id", clientId);
            }
            if (bearerToken != null) {
                builder.header("Authorization", "Bearer " + bearerToken);
            }
            HttpRequest.BodyPublisher publisher = jsonBody == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(jsonBody);
            builder.method(method, publisher);
            if (jsonBody != null) {
                builder.header("Content-Type", "application/json");
            }
            HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            JsonNode json = parse(response.body());
            return new Result(response.statusCode(),
                    text(json, "error"),
                    text(json, "reason"),
                    text(json, "accessToken"),
                    text(json, "refreshToken"),
                    text(json, "sessionId"),
                    text(json, "message"),
                    json);
        } catch (Exception e) {
            throw new RuntimeException("HTTP 调用失败: " + method + " " + path, e);
        }
    }

    private static JsonNode parse(String body) {
        try {
            return body == null || body.isBlank() ? null : MAPPER.readTree(body);
        } catch (Exception e) {
            return null;
        }
    }

    private static String text(JsonNode node, String field) {
        return node == null || !node.has(field) || node.get(field).isNull() ? null : node.get(field).asText();
    }

    private static String toJson(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String mask(String token) {
        if (token == null) {
            return "<缺失>";
        }
        int dot = token.lastIndexOf('.');
        String id = dot >= 0 ? token.substring(dot + 1) : token;
        String prefix = token.startsWith("atk") ? "atk" : token.startsWith("rtk") ? "rtk" : "?";
        return prefix + "..." + (id.length() > 8 ? id.substring(0, 8) : id);
    }

    private static String tokenStateDescription(Result result) {
        if (result.status() == 200) {
            return "请求成功，新/原令牌有效";
        }
        return "被拒绝(" + result.errorCode() + ")";
    }

    public record Result(int status, String errorCode, String reason, String accessToken,
                         String refreshToken, String sessionId, String message, JsonNode raw) {
    }
}
