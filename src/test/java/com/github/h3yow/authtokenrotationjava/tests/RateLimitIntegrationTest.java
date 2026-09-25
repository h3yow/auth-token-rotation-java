package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.support.HttpTestClient;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 按调用方身份维度的限流边界测试：
 * 窗口内恰好放行 N 个、第 N+1 个稳定拒绝；窗口滑过后配额恢复；
 * 不同调用方互不影响；同一调用方并发计数不漏放。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(com.github.h3yow.authtokenrotationjava.support.TestClockConfiguration.class)
@TestPropertySource(properties = {
        "auth.token.access-ttl=PT5M",
        "auth.token.refresh-ttl=PT30M",
        "auth.token.replay-grace-window=PT0.5S",
        "auth.ratelimit.max-requests=5",
        "auth.ratelimit.window=PT10S"
})
class RateLimitIntegrationTest extends AbstractIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger("TEST");

    @Test
    void authEndpoint_boundaryExactlyNAllowedThenRejected_windowSlidesRecovery() {
        String clientA = "rl-client-a";
        String clientB = "rl-client-b";

        // 窗口 [0s, 10s) 内：5 个放行，第 6 个拒绝
        List<HttpTestClient.Result> results = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            results.add(http().login(clientA, "u" + i, "password"));
        }
        for (int i = 0; i < 5; i++) {
            assertEquals(200, results.get(i).status(),
                    "窗口内前 5 个请求必须放行，第 " + (i + 1) + " 个被误伤");
        }
        assertRejected(results.get(5), 429, "RATE_LIMITED");

        // 另一调用方不受影响
        for (int i = 0; i < 5; i++) {
            assertEquals(200, http().login(clientB, "b" + i, "password").status(),
                    "不同调用方之间必须互不影响");
        }
        assertRejected(http().login(clientB, "overflow", "password"), 429, "RATE_LIMITED");

        // client A 即便使用不同用户名/路径，仍受同一 clientId 维度约束
        assertRejected(http().refresh(clientA, "rtk.x.y"), 429, "RATE_LIMITED");

        // 时钟推进到窗口滑过：最早的请求时间戳离开窗口，配额恢复
        clock.advance(Duration.ofSeconds(10).plusMillis(1));
        HttpTestClient.Result recovered = http().login(clientA, "recovered", "password");
        assertEquals(200, recovered.status(), "窗口滑过后配额必须恢复，不得持续误伤");

        log.info("[TEST 断言] 场景=限流边界 | clientA={} clientB={} | 依据=每窗口5次，"
                        + "第6次429，跨client隔离，窗口滑过恢复", clientA, clientB);
    }

    @Test
    void slidingWindow_boundaryTimestampsLeaveOneByOne() {
        String client = "rl-sliding";
        // t=0 打满 5 次
        for (int i = 0; i < 5; i++) {
            assertEquals(200, http().login(client, "u" + i, "password").status());
        }
        assertRejected(http().login(client, "blocked", "password"), 429, "RATE_LIMITED");

        // 推进 5 秒：仍处于 10 秒窗口内，依旧拒绝（无漏放）
        clock.advance(Duration.ofSeconds(5));
        assertRejected(http().login(client, "stillBlocked", "password"), 429, "RATE_LIMITED");

        // 推进到恰好 t=10s+1ms：t=0 的 5 个时间戳全部离开窗口，恢复恰好 5 个配额
        clock.advance(Duration.ofSeconds(5).plusMillis(1));
        for (int i = 0; i < 5; i++) {
            assertEquals(200, http().login(client, "v" + i, "password").status(),
                    "旧时间戳离开窗口后必须精确恢复配额");
        }
        assertRejected(http().login(client, "overflow2", "password"), 429, "RATE_LIMITED");

        log.info("[TEST 断言] 场景=滑动窗口边界 | clientId={} | 依据=窗口外时间戳被剔除后计数精确恢复",
                client);
    }

    @Test
    void concurrentRequests_noLeakBeyondQuota() throws Exception {
        String client = "rl-concurrent";
        int threads = 20;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<HttpTestClient.Result>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                final int idx = i;
                futures.add(pool.submit(() -> {
                    start.await();
                    return http().login(client, "c" + idx, "password");
                }));
            }
            start.countDown();
            int allowed = 0;
            int limited = 0;
            Set<Integer> statuses = new HashSet<>();
            for (Future<HttpTestClient.Result> future : futures) {
                HttpTestClient.Result result = future.get(20, TimeUnit.SECONDS);
                statuses.add(result.status());
                if (result.status() == 200) {
                    allowed++;
                } else if ("RATE_LIMITED".equals(result.errorCode())) {
                    limited++;
                }
            }
            log.info("[TEST 断言] 场景=并发限流 | clientId={} | 并发={} | 放行={} | 限流={} | "
                            + "依据=per-client 段内同步，滑动窗口计数原子", client, threads, allowed, limited);
            assertEquals(5, allowed, "并发场景下放行数必须恰好等于配额，不得漏放");
            assertEquals(threads - 5, limited, "超出配额的并发请求必须稳定拒绝");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void apiEndpoint_rateLimitedByTokenBoundClientIdentity() {
        // 资源接口用另一调用方登录（占用其独立计数），其 /api 调用同样受限流约束
        String client = "rl-api";
        HttpTestClient.Result issued = http().login(client, "erin", "password");
        assertEquals(200, issued.status());

        // 已消耗 1 次（login），还剩 4 次
        for (int i = 0; i < 4; i++) {
            assertEquals(200, http().ping(client, issued.accessToken()).status());
        }
        assertRejected(http().ping(client, issued.accessToken()), 429, "RATE_LIMITED");

        // 伪造 X-Client-Id 不能改变限流维度：身份以服务端令牌绑定为准
        assertRejected(http().pingWithAnyHeader("someone-else", issued.accessToken()),
                429, "RATE_LIMITED");

        log.info("[TEST 断言] 场景=资源接口限流 | clientId={} | 依据=限流身份取自令牌绑定，伪造头无效",
                client);
    }
}
