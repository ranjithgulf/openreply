import { createHmac } from "crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getMissingInstagramOAuthEnv } from "../lib/env";
import {
  getDefaultMetaLoginMethod,
  isFacebookGraphToken,
  parseMetaLoginMethod,
} from "../lib/meta/login-method";
import {
  createOAuthState,
  getAuthorizationUrl,
  getFacebookAuthorizationUrl,
  verifyOAuthState,
} from "../lib/meta/oauth";
import {
  getFacebookPagesWithInstagram,
  getUserInfo,
  getUserMedia,
  refreshLongLivedToken,
  sendDirectMessage,
  sendPrivateReply,
  subscribeInstagramAccountToWebhooks,
  TokenExpiredError,
} from "../lib/meta/client";

const IG_TOKEN = "IGAAtest-instagram-token";
const PAGE_TOKEN = "EAAtest-page-token";
type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;
const KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function json(body: unknown, url = "https://graph.example/") {
  const response = new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
  Object.defineProperty(response, "url", { value: url });
  return response;
}

beforeEach(() => {
  vi.unstubAllEnvs();
  vi.stubEnv("NEXTAUTH_SECRET", "test-secret-with-enough-length");
  vi.stubEnv("ENCRYPTION_KEY", KEY);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("login method selection", () => {
  it("parses method names, accepting 'unified' as Facebook Login", () => {
    expect(parseMetaLoginMethod("instagram")).toBe("instagram");
    expect(parseMetaLoginMethod(" Facebook ")).toBe("facebook");
    expect(parseMetaLoginMethod("unified")).toBe("facebook");
    expect(parseMetaLoginMethod("other")).toBeNull();
    expect(parseMetaLoginMethod(null)).toBeNull();
  });

  it("defaults to Instagram Login so existing deployments are unchanged", () => {
    expect(getDefaultMetaLoginMethod()).toBe("instagram");
    vi.stubEnv("META_LOGIN_METHOD", "unified");
    expect(getDefaultMetaLoginMethod()).toBe("facebook");
  });

  it("tells token kinds apart by prefix", () => {
    expect(isFacebookGraphToken(PAGE_TOKEN)).toBe(true);
    expect(isFacebookGraphToken(IG_TOKEN)).toBe(false);
  });
});

describe("OAuth environment checks", () => {
  it("treats .env.example placeholders as missing", () => {
    vi.stubEnv("INSTAGRAM_APP_ID", "your-instagram-app-id");
    vi.stubEnv("INSTAGRAM_APP_SECRET", "real-secret");
    expect(getMissingInstagramOAuthEnv("instagram")).toEqual(["INSTAGRAM_APP_ID"]);
  });

  it("requires the Facebook app ID, secret and configuration ID for Unified Login", () => {
    vi.stubEnv("FACEBOOK_APP_SECRET", "your-facebook-app-secret");
    expect(getMissingInstagramOAuthEnv("facebook")).toEqual([
      "FACEBOOK_APP_ID",
      "FACEBOOK_APP_SECRET",
      "META_LOGIN_CONFIG_ID",
    ]);
    vi.stubEnv("FACEBOOK_APP_ID", "1593499326134313");
    vi.stubEnv("FACEBOOK_APP_SECRET", "real-secret");
    vi.stubEnv("META_LOGIN_CONFIG_ID", "123456789");
    expect(getMissingInstagramOAuthEnv("facebook")).toEqual([]);
  });
});

describe("OAuth state carries the login method", () => {
  it("round-trips the method", () => {
    expect(verifyOAuthState(createOAuthState("ws", "facebook"))?.method).toBe("facebook");
    expect(verifyOAuthState(createOAuthState("ws"))?.method).toBe("instagram");
  });

  it("reads a state minted before the method existed as Instagram Login", () => {
    const payload = Buffer.from(
      JSON.stringify({ workspaceId: "ws", ts: Date.now() })
    ).toString("base64url");
    const signature = createHmac("sha256", "test-secret-with-enough-length")
      .update(payload)
      .digest("base64url");
    expect(verifyOAuthState(`${payload}.${signature}`)?.method).toBe("instagram");
  });

  it("rejects an unknown method", () => {
    const payload = Buffer.from(
      JSON.stringify({ workspaceId: "ws", ts: Date.now(), method: "x" })
    ).toString("base64url");
    const signature = createHmac("sha256", "test-secret-with-enough-length")
      .update(payload)
      .digest("base64url");
    expect(verifyOAuthState(`${payload}.${signature}`)).toBeNull();
  });
});

describe("authorization URLs", () => {
  const redirect = "https://openreply.gizoauto.com/api/instagram/callback";

  it("keeps the Instagram Login URL unchanged", () => {
    vi.stubEnv("INSTAGRAM_APP_ID", "111");
    const url = new URL(getAuthorizationUrl(redirect, "s"));
    expect(url.origin + url.pathname).toBe("https://www.instagram.com/oauth/authorize");
    expect(url.searchParams.get("client_id")).toBe("111");
  });

  it("builds the Facebook Login for Business dialog with config_id and no scope", () => {
    vi.stubEnv("FACEBOOK_APP_ID", "1593499326134313");
    vi.stubEnv("META_LOGIN_CONFIG_ID", "987654321");
    const url = new URL(getFacebookAuthorizationUrl(redirect, "s"));
    expect(url.origin + url.pathname).toBe("https://www.facebook.com/v25.0/dialog/oauth");
    expect(url.searchParams.get("client_id")).toBe("1593499326134313");
    expect(url.searchParams.get("config_id")).toBe("987654321");
    expect(url.searchParams.get("redirect_uri")).toBe(redirect);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.has("scope")).toBe(false);
  });
});

describe("Graph routing by token", () => {
  it("sends Instagram Login messages to graph.instagram.com/{ig-id}/messages", async () => {
    const fetchMock = vi.fn<FetchLike>(async () => json({ recipient_id: "u", message_id: "m" }));
    vi.stubGlobal("fetch", fetchMock);
    await sendDirectMessage(IG_TOKEN, "17841400000000000", "user", "hi");
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://graph.instagram.com/v25.0/17841400000000000/messages"
    );
  });

  it("sends Unified Login messages and private replies through the Page", async () => {
    const fetchMock = vi.fn<FetchLike>(async () => json({ recipient_id: "u", message_id: "m" }));
    vi.stubGlobal("fetch", fetchMock);
    await sendDirectMessage(PAGE_TOKEN, "17841400000000000", "user", "hi");
    await sendPrivateReply(PAGE_TOKEN, "17841400000000000", "comment", "hi");
    expect(fetchMock.mock.calls[0][0]).toBe("https://graph.facebook.com/v25.0/me/messages");
    expect(fetchMock.mock.calls[1][0]).toBe("https://graph.facebook.com/v25.0/me/messages");
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body)).recipient).toEqual({
      comment_id: "comment",
    });
  });

  it("reads Unified Login profile and media from the Page's Instagram account", async () => {
    const fetchMock = vi.fn(async (input: string) => {
      const url = new URL(input);
      if (url.pathname === "/v25.0/me") {
        return json({ id: "page1", instagram_business_account: { id: "17841499" } });
      }
      if (url.pathname === "/v25.0/17841499") {
        return json({ id: "17841499", username: "ranj_ith1265" });
      }
      return json({ data: [{ id: "media1", media_type: "IMAGE", timestamp: "t" }] });
    });
    vi.stubGlobal("fetch", fetchMock);

    const user = await getUserInfo(`${PAGE_TOKEN}-profile`);
    expect(user).toMatchObject({ id: "17841499", user_id: "17841499", username: "ranj_ith1265" });

    const media = await getUserMedia(`${PAGE_TOKEN}-profile`);
    expect(media).toHaveLength(1);
    const mediaCall = fetchMock.mock.calls.map((c) => new URL(c[0]).pathname);
    expect(mediaCall).toContain("/v25.0/17841499/media");
    // The Page lookup is cached, so it ran once for both reads.
    expect(mediaCall.filter((p) => p === "/v25.0/me")).toHaveLength(1);
  });

  it("subscribes the Page for Unified Login and the IG account otherwise", async () => {
    const fetchMock = vi.fn<FetchLike>(async () => json({ success: true }));
    vi.stubGlobal("fetch", fetchMock);
    await subscribeInstagramAccountToWebhooks("17841499", PAGE_TOKEN);
    await subscribeInstagramAccountToWebhooks("17841499", IG_TOKEN);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://graph.facebook.com/v25.0/me/subscribed_apps?subscribed_fields=feed"
    );
    expect(fetchMock.mock.calls[1][0]).toBe(
      "https://graph.instagram.com/v25.0/17841499/subscribed_apps"
    );
  });

  it("does not send a Page token to the Instagram refresh endpoint", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(refreshLongLivedToken(PAGE_TOKEN)).rejects.toBeInstanceOf(TokenExpiredError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps only granted Pages that have a linked Instagram account", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        json({
          data: [
            {
              id: "p1",
              name: "GizoAuto Demo",
              access_token: "EAApage1",
              instagram_business_account: { id: "17841499", username: "ranj_ith1265" },
            },
            { id: "p2", name: "No IG", access_token: "EAApage2" },
          ],
        })
      )
    );
    const pages = await getFacebookPagesWithInstagram("EAAuser");
    expect(pages).toEqual([
      {
        pageId: "p1",
        pageName: "GizoAuto Demo",
        pageAccessToken: "EAApage1",
        instagramId: "17841499",
        instagramUsername: "ranj_ith1265",
        instagramName: undefined,
      },
    ]);
  });
});
