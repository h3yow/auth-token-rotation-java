package com.github.h3yow.authtokenrotationjava.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 按调用方身份（clientId）维度的滑动窗口限流器。
 *
 * <p>采用滑动日志（sliding window log）：为每个调用方维护窗口内的请求时间戳，
 * 判定前先剔除窗口外的旧时间戳，再与配额比较。这样在时间窗边界附近既不会
 * 漏放（旧请求一过期立即让出配额），也不会误伤（窗口内请求数严格不超过配额）。</p>
 *
 * <p>计数状态按 clientId 分段并在段内同步：同一调用方的并发请求判定是原子的，
 * 不同调用方各自独立、互不影响。</p>
 */
public class ClientRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(ClientRateLimiter.class);

    private final Clock clock;
    private final int maxRequests;
    private final Duration window;
    private final ConcurrentMap<String, Deque<Long>> windows = new ConcurrentHashMap<>();

    public ClientRateLimiter(Clock clock, int maxRequests, Duration window) {
        this.clock = clock;
        this.maxRequests = maxRequests;
        this.window = window;
    }

    /**
     * 尝试占用一个配额。
     *
     * @return true 放行；false 表示该调用方在当前滑动窗口内已超限
     */
    public boolean tryAcquire(String clientId) {
        long now = clock.millis();
        long windowStart = now - window.toMillis() + 1;
        Deque<Long> timestamps = windows.computeIfAbsent(clientId, k -> new ArrayDeque<>());
        synchronized (timestamps) {
            while (!timestamps.isEmpty() && timestamps.peekFirst() < windowStart) {
                timestamps.pollFirst();
            }
            if (timestamps.size() >= maxRequests) {
                log.warn("限流命中 | clientId={} | 当前窗口计数={} | 上限={} | 窗口={}ms | 判定依据=窗口内请求数已达上限",
                        clientId, timestamps.size(), maxRequests, window.toMillis());
                return false;
            }
            timestamps.addLast(now);
            return true;
        }
    }

    /** 当前窗口内该调用方已使用的请求数（用于日志/测试断言）。 */
    public int currentCount(String clientId) {
        long now = clock.millis();
        long windowStart = now - window.toMillis() + 1;
        Deque<Long> timestamps = windows.get(clientId);
        if (timestamps == null) {
            return 0;
        }
        synchronized (timestamps) {
            while (!timestamps.isEmpty() && timestamps.peekFirst() < windowStart) {
                timestamps.pollFirst();
            }
            return timestamps.size();
        }
    }

    /** 清除某调用方的计数（测试用）。 */
    public void reset(String clientId) {
        windows.remove(clientId);
    }
}
