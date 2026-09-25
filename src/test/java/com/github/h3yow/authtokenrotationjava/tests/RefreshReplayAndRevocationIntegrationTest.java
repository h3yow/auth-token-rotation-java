package com.github.h3yow.authtokenrotationjava.tests;

import com.github.h3yow.authtokenrotationjava.support.HttpTestClient;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * 覆盖：正常轮换链、宽限窗口内重复刷新（并发竞争原因）、窗口外旧令牌重放
 * （整条链路撤销且结论可区分）、注销后未过期访问令牌立即不可用、过期访问令牌。
 */
@TestPropertySource(properties = "auth.token.replay-grace-window=PT0.5S")
class RefreshReplayAndRevocationIntegrationTest extends AbstractIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger("TEST");

    @Test
    void sequentialRotation_oldTokenReplayAfterGraceWindow_revokesWholeFamily() {
        String clientId = "client-replay";
        HttpTestClient.Result first = http().login(clientId, "alice", "password");
        assertEquals(200, first.status());
        String firstRefresh = first.refreshToken();
        String firstAccess = first.accessToken();

        // 第一次正常轮换成功，得到第二代令牌对
        HttpTestClient.Result second = http().refresh(clientId, firstRefresh);
        assertEquals(200, second.status());
        String secondRefresh = second.refreshToken();
        String secondAccess = second.accessToken();
        assertNotEquals(firstRefresh, secondRefresh);

        // 第一代令牌在宽限窗口内被再次使用：判为并发竞争落败，链路不撤销
        clock.advance(Duration.ofMillis(100));
        HttpTestClient.Result race = http().refresh(clientId, firstRefresh);
        assertRejected(race, 401, "REFRESH_CONCURRENT_RACE");

        // 第二代刷新令牌仍然有效（合法会话未被误伤），轮换出第三代
        HttpTestClient.Result third = http().refresh(clientId, secondRefresh);
        assertEquals(200, third.status(), "宽限窗口内的竞争落败不应撤销链路");
        String thirdRefresh = third.refreshToken();

        // 第一代令牌此时已属"更早代际"：即使时钟仍在宽限窗口内，再次使用也确定性地判定为重放
        HttpTestClient.Result oldGenerationReplay = http().refresh(clientId, firstRefresh);
        assertRejected(oldGenerationReplay, 401, "REFRESH_REPLAY_DETECTED");

        // 重放结论必须对整条链路生效：最新刷新令牌立即不可用
        HttpTestClient.Result latestRefreshAfterReplay = http().refresh(clientId, thirdRefresh);
        assertRejected(latestRefreshAfterReplay, 401, "REFRESH_FAMILY_REVOKED");

        // 重放时未过期的各代访问令牌都必须立即不可用（失效传播）
        assertRejected(http().ping(clientId, secondAccess), 401, "SESSION_REVOKED");
        assertRejected(http().ping(clientId, firstAccess), 401, "SESSION_REVOKED");

        // 再次重放同一旧令牌，结论保持稳定可区分（链路已撤销）
        clock.advance(Duration.ofSeconds(1));
        assertRejected(http().refresh(clientId, firstRefresh), 401, "REFRESH_FAMILY_REVOKED");

        log.info("[TEST 断言] 场景=顺序重放 | clientId={} | 依据=更早代际已消费刷新令牌再次使用即判重放，"
                        + "family 整体撤销并传播到所有未过期访问令牌", clientId);
    }

    @Test
    void latestGenerationReplayAfterGraceWindow_isDetectedAsReplay() {
        String clientId = "client-replay-window";
        HttpTestClient.Result first = http().login(clientId, "alice", "password");
        assertEquals(200, first.status());

        HttpTestClient.Result second = http().refresh(clientId, first.refreshToken());
        assertEquals(200, second.status());

        // 最新一代被消费令牌在宽限窗口（测试配置 500ms）内重复：并发竞争，链路保留
        clock.advance(Duration.ofMillis(200));
        assertRejected(http().refresh(clientId, first.refreshToken()),
                401, "REFRESH_CONCURRENT_RACE");

        // 越过宽限窗口后，最新一代的旧令牌再次使用：重放，链路撤销
        clock.advance(Duration.ofMillis(400));
        assertRejected(http().refresh(clientId, first.refreshToken()),
                401, "REFRESH_REPLAY_DETECTED");

        assertRejected(http().refresh(clientId, second.refreshToken()),
                401, "REFRESH_FAMILY_REVOKED");

        log.info("[TEST 断言] 场景=时间窗边界重放 | clientId={} | 依据=最新代际超过宽限窗口即判重放",
                clientId);
    }

    @Test
    void logout_unexpiredAccessTokenBecomesUnusableImmediately() {
        String clientId = "client-logout";
        HttpTestClient.Result issued = http().login(clientId, "carol", "password");
        assertEquals(200, issued.status());

        // 注销前访问令牌可用
        assertEquals(200, http().ping(clientId, issued.accessToken()).status());

        // 注销会话
        HttpTestClient.Result logout = http().logout(clientId, issued.accessToken());
        assertEquals(200, logout.status());

        // 时钟未推进，访问令牌尚未过期，但必须立即不可用
        HttpTestClient.Result afterLogout = http().ping(clientId, issued.accessToken());
        assertRejected(afterLogout, 401, "SESSION_REVOKED");

        // 刷新链路也被撤销
        HttpTestClient.Result refreshAfterLogout = http().refresh(clientId, issued.refreshToken());
        assertRejected(refreshAfterLogout, 401, "REFRESH_FAMILY_REVOKED");

        log.info("[TEST 断言] 场景=注销传播 | clientId={} | 依据=会话级撤销立即使所有未过期访问令牌失效",
                clientId);
    }

    @Test
    void unknownAndMalformedTokens_areRejectedWithDistinguishableReasons() {
        String clientId = "client-badtoken";

        assertRejected(http().refresh(clientId, "rtk.deadbeef.deadbeef"), 401, "REFRESH_TOKEN_UNKNOWN");
        assertRejected(http().refresh(clientId, "not-a-token"), 401, "REFRESH_TOKEN_UNKNOWN");
        assertRejected(http().ping(clientId, "atk.deadbeef.deadbeef"), 401, "ACCESS_TOKEN_UNKNOWN");

        log.info("[TEST 断言] 场景=非法令牌 | clientId={} | 依据=无法解析或查无此令牌，返回 UNKNOWN 原因",
                clientId);
    }

    @Test
    void expiredAccessToken_isRejectedAsExpired() {
        String clientId = "client-expiry";
        HttpTestClient.Result issued = http().login(clientId, "dave", "password");
        assertEquals(200, issued.status());

        // 推进超过访问令牌 TTL（5 分钟）但刷新令牌仍在 30 分钟 TTL 内
        clock.advance(Duration.ofMinutes(6));
        HttpTestClient.Result expiredAccess = http().ping(clientId, issued.accessToken());
        assertRejected(expiredAccess, 401, "ACCESS_TOKEN_EXPIRED");

        // 刷新令牌未过期，可以换取新令牌对
        HttpTestClient.Result rotated = http().refresh(clientId, issued.refreshToken());
        assertEquals(200, rotated.status());
        assertEquals(200, http().ping(clientId, rotated.accessToken()).status());

        log.info("[TEST 断言] 场景=访问令牌过期 | clientId={} | 依据=当前时间晚于 expiresAt，"
                        + "但刷新链路仍有效", clientId);
    }
}
