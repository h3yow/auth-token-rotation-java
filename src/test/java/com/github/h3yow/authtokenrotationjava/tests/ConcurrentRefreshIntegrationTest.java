package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.support.HttpTestClient;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 同一刷新令牌被并发使用：必须恰好一次成功，其余以可区分原因拒绝，
 * 且不得误伤同一调用方的其他合法会话。
 */
class ConcurrentRefreshIntegrationTest extends AbstractIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger("TEST");

    @Test
    void concurrentRefresh_sameToken_onlyOneSucceedsOthersDistinguishablyRejected() throws Exception {
        String clientId = "client-concurrent";
        HttpTestClient.Result issued = http().login(clientId, "alice", "password");
        assertEquals(200, issued.status());
        String refreshToken = issued.refreshToken();

        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<HttpTestClient.Result>> futures = IntStream.range(0, threads)
                    .<Callable<HttpTestClient.Result>>mapToObj(i -> () -> {
                        start.await();
                        return http().refresh(clientId, refreshToken);
                    })
                    .map(pool::submit)
                    .toList();
            start.countDown();

            int success = 0;
            int concurrentRace = 0;
            int replay = 0;
            int otherRejections = 0;
            Set<String> issuedNewRefreshTokens = new HashSet<>();
            for (Future<HttpTestClient.Result> future : futures) {
                HttpTestClient.Result result = future.get(20, TimeUnit.SECONDS);
                if (result.status() == 200) {
                    success++;
                    issuedNewRefreshTokens.add(result.refreshToken());
                } else if ("REFRESH_CONCURRENT_RACE".equals(result.errorCode())) {
                    concurrentRace++;
                } else if ("REFRESH_REPLAY_DETECTED".equals(result.errorCode())) {
                    replay++;
                } else {
                    otherRejections++;
                }
            }

            log.info("[TEST 断言] 场景=并发刷新 | clientId={} | 线程数={} | 成功数={} | 并发竞争落败数={} | 重放数={} | "
                            + "其他拒绝={} | 依据=同一刷新令牌原子轮换，固定时钟下落败方确定性判为并发竞争",
                    clientId, threads, success, concurrentRace, replay, otherRejections);

            assertEquals(1, success, "同一刷新令牌的并发刷新必须恰好一次成功");
            assertEquals(0, replay, "并发竞争不得被误判为重放（会误伤合法会话）");
            assertEquals(0, otherRejections, "落败请求必须以可区分的并发竞争原因拒绝");
            assertEquals(threads - 1, concurrentRace, "其余请求必须全部判为并发竞争落败");
            assertEquals(1, issuedNewRefreshTokens.size(), "成功轮换只能产生一个新刷新令牌");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void concurrentRace_doesNotHarmOtherValidSessions() throws Exception {
        String clientId = "client-isolation";

        HttpTestClient.Result sessionA = http().login(clientId, "alice", "password");
        HttpTestClient.Result sessionB = http().login(clientId, "bob", "password");
        assertEquals(200, sessionA.status());
        assertEquals(200, sessionB.status());

        // 对会话 A 的刷新令牌制造并发竞争
        int threads = 4;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<HttpTestClient.Result>> futures = IntStream.range(0, threads)
                    .<Callable<HttpTestClient.Result>>mapToObj(i -> () -> {
                        start.await();
                        return http().refresh(clientId, sessionA.refreshToken());
                    })
                    .map(pool::submit)
                    .toList();
            start.countDown();
            int success = 0;
            for (Future<HttpTestClient.Result> future : futures) {
                if (future.get(20, TimeUnit.SECONDS).status() == 200) {
                    success++;
                }
            }
            assertEquals(1, success);
        } finally {
            pool.shutdownNow();
        }

        // 会话 B 是完全独立的刷新链路，其未过期访问令牌与刷新必须仍然有效
        HttpTestClient.Result bAccess = http().ping(clientId, sessionB.accessToken());
        assertEquals(200, bAccess.status(), "其他合法会话的访问令牌不得被误伤");

        HttpTestClient.Result bRotated = http().refresh(clientId, sessionB.refreshToken());
        assertEquals(200, bRotated.status(), "其他合法会话的刷新链路必须保持可用");
        log.info("[TEST 断言] 场景=会话隔离 | clientId={} | 依据=family 级原子锁不影响其他链路 | sessionB 仍可访问与刷新",
                clientId);
    }
}
