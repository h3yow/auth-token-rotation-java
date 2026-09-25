package com.github.h3yow.authtokenrotationjava.domain;

/**
 * 可区分的鉴权/限流失败原因。每一个判定结论都对应稳定的错误码，
 * 测试与调用方可以据此复现与解释鉴权结论。
 */
public enum AuthErrorCode {

    // ---- 签发 ----
    LOGIN_INVALID("用户名或密码错误"),

    // ---- 访问 ----
    ACCESS_TOKEN_MISSING("缺少访问令牌"),
    ACCESS_TOKEN_UNKNOWN("访问令牌不存在或无法识别"),
    ACCESS_TOKEN_EXPIRED("访问令牌已过期"),
    SESSION_REVOKED("会话已注销或被撤销，访问令牌立即失效"),

    // ---- 刷新 ----
    REFRESH_TOKEN_MISSING("缺少刷新令牌"),
    REFRESH_TOKEN_UNKNOWN("刷新令牌不存在或无法识别"),
    REFRESH_TOKEN_EXPIRED("刷新令牌已过期"),
    REFRESH_FAMILY_REVOKED("刷新链路已因重放被整体撤销"),
    REFRESH_CONCURRENT_RACE("同一刷新令牌在并发竞争中已被使用，本次请求落败"),
    REFRESH_REPLAY_DETECTED("检测到旧刷新令牌重放，整条刷新链路已被撤销"),

    // ---- 撤销 ----
    REFRESH_TOKEN_REVOKED("刷新令牌所属会话已被显式撤销"),

    // ---- 限流 ----
    RATE_LIMITED("超过调用方请求频率上限"),
    CLIENT_ID_MISSING("缺少调用方标识 X-Client-Id，无法进行身份维度判定");

    private final String description;

    AuthErrorCode(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
