package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.support.HttpTestClient;
import com.github.h3yow.authtokenrotationjava.support.MutableClock;
import com.github.h3yow.authtokenrotationjava.support.TestClockConfiguration;
import org.junit.jupiter.api.Assertions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;

/**
 * 集成测试基类：随机端口启动完整 HTTP 服务，注入可拨动时钟与测试客户端。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "auth.token.access-ttl=PT5M",
                "auth.token.refresh-ttl=PT30M",
                "auth.token.replay-grace-window=PT0.5S",
                "auth.ratelimit.max-requests=1000",
                "auth.ratelimit.window=PT10S"
        })
@Import(TestClockConfiguration.class)
public abstract class AbstractIntegrationTest {

    @LocalServerPort
    protected int port;

    @Autowired
    protected MutableClock clock;

    protected HttpTestClient http;

    protected HttpTestClient http() {
        if (http == null) {
            http = new HttpTestClient("http://localhost:" + port);
        }
        return http;
    }

    protected HttpTestClient.Result assertRejected(HttpTestClient.Result result, int httpStatus, String errorCode) {
        Assertions.assertEquals(httpStatus, result.status(),
                "期望请求被拒绝，但实际 HTTP 状态=" + result.status() + " body=" + result.raw());
        Assertions.assertEquals(errorCode, result.errorCode(),
                "失败原因必须可区分；期望 error=" + errorCode + "，实际=" + result.errorCode()
                        + " reason=" + result.reason());
        return result;
    }
}
