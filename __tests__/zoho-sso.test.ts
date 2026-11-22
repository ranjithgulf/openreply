import { describe, expect, it } from "vitest";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWTPayload } from "jose";
import {
  authorizeZohoSignIn,
  getZohoSettings,
  isVerifiedEmailClaim,
  isZohoEmailAuthorized,
  verifyZohoIdToken,
  zohoProvider,
  type ZohoSettings,
} from "../lib/zoho-sso";

const SSO = "https://directory.zoho.com/p/948196904/app/1387085000000002039/sso";
const ISSUER = "https://accounts.zoho.com/oauthapp/1002-948196904";

const baseEnv = {
  AUTH_ZOHO_ID: "client-id",
  AUTH_ZOHO_SECRET: "client-secret",
  AUTH_ZOHO_ISSUER: ISSUER,
  AUTH_ZOHO_SSO_URL: `${SSO}/`,
};

const settings: ZohoSettings = {
  clientId: "client-id",
  clientSecret: "client-secret",
  issuer: ISSUER,
  ssoUrl: SSO,
};

describe("Zoho settings", () => {
  it("is disabled unless every value is present", () => {
    expect(getZohoSettings({})).toBeNull();
    expect(getZohoSettings({ ...baseEnv, AUTH_ZOHO_SECRET: "" })).toBeNull();
    expect(getZohoSettings({ ...baseEnv, AUTH_ZOHO_ISSUER: undefined })).toBeNull();
  });

  it("rejects non-HTTPS endpoints", () => {
    expect(getZohoSettings({ ...baseEnv, AUTH_ZOHO_SSO_URL: "http://directory.zoho.com/x/sso" })).toBeNull();
    expect(getZohoSettings({ ...baseEnv, AUTH_ZOHO_ISSUER: "not a url" })).toBeNull();
  });

  it("normalizes trailing slashes", () => {
    expect(getZohoSettings(baseEnv)).toEqual(settings);
  });

  it("uses the app-specific endpoints and keeps the org issuer", () => {
    const provider = zohoProvider(settings);
    expect(provider.issuer).toBe(ISSUER);
    expect(provider.authorization).toMatchObject({ url: `${SSO}/authorize` });
    expect(provider.token).toBe(`${SSO}/token`);
    expect(provider.userinfo).toBe(`${SSO}/userinfo`);
    expect(provider.checks).toEqual(["pkce", "state", "nonce"]);
    expect(provider).not.toHaveProperty("allowDangerousEmailAccountLinking");
  });

  it("maps the profile with a lowercased email", () => {
    const profile = zohoProvider(settings).profile!(
      { sub: "123", email: " Ana@Example.COM ", first_name: "Ana", last_name: "Lima" },
      {},
    );
    expect(profile).toEqual({ id: "123", email: "ana@example.com", name: "Ana Lima", image: null });
  });
});

describe("Zoho allowlist", () => {
  it("fails closed when nothing is configured", () => {
    expect(isZohoEmailAuthorized("ana@example.com", {})).toBe(false);
  });

  it("matches exact addresses and exact domains only", () => {
    const env = { ZOHO_ALLOWED_EMAILS: "boss@other.com", ZOHO_ALLOWED_DOMAINS: "@Example.com" };
    expect(isZohoEmailAuthorized("BOSS@other.com", env)).toBe(true);
    expect(isZohoEmailAuthorized("ana@example.com", env)).toBe(true);
    expect(isZohoEmailAuthorized("ana@sub.example.com", env)).toBe(false);
    expect(isZohoEmailAuthorized("ana@example.com.evil.io", env)).toBe(false);
    expect(isZohoEmailAuthorized("someone@other.com", env)).toBe(false);
    expect(isZohoEmailAuthorized("example.com", env)).toBe(false);
  });

  it("accepts only a true email_verified claim", () => {
    expect(isVerifiedEmailClaim(true)).toBe(true);
    expect(isVerifiedEmailClaim("true")).toBe(true);
    expect(isVerifiedEmailClaim(false)).toBe(false);
    expect(isVerifiedEmailClaim(undefined)).toBe(false);
    expect(isVerifiedEmailClaim("yes")).toBe(false);
  });
});

describe("authorizeZohoSignIn", () => {
  const env = { ZOHO_ALLOWED_DOMAINS: "example.com" };
  const account = { providerAccountId: "sub-1", id_token: "token" };
  const verifyWith = (claims: JWTPayload) => async () => claims;

  it("allows a verified, allowlisted user", async () => {
    const result = await authorizeZohoSignIn(
      { account },
      { settings, env, verify: verifyWith({ sub: "sub-1", email: "Ana@example.com", email_verified: true }) },
    );
    expect(result).toEqual({ ok: true, email: "ana@example.com" });
  });

  it.each([
    ["not-configured", { settings: null }],
    ["invalid-id-token", { verify: async () => { throw new Error("bad signature"); } }],
    ["subject-mismatch", { verify: verifyWith({ sub: "other", email: "ana@example.com", email_verified: true }) }],
    ["email-missing", { verify: verifyWith({ sub: "sub-1", email_verified: true }) }],
    ["email-unverified", { verify: verifyWith({ sub: "sub-1", email: "ana@example.com", email_verified: false }) }],
    ["not-allowed", { verify: verifyWith({ sub: "sub-1", email: "ana@elsewhere.com", email_verified: true }) }],
  ] as const)("rejects with %s", async (reason, deps) => {
    const result = await authorizeZohoSignIn({ account }, { settings, env, ...deps });
    expect(result).toEqual({ ok: false, reason });
  });

  it("rejects a missing ID token", async () => {
    const result = await authorizeZohoSignIn({ account: { providerAccountId: "sub-1" } }, { settings, env });
    expect(result).toEqual({ ok: false, reason: "missing-id-token" });
  });

  it("also honours the instance-wide ALLOWED_EMAILS check", async () => {
    const result = await authorizeZohoSignIn(
      { account },
      {
        settings,
        env,
        instanceAllows: () => false,
        verify: verifyWith({ sub: "sub-1", email: "ana@example.com", email_verified: true }),
      },
    );
    expect(result).toEqual({ ok: false, reason: "not-allowed" });
  });
});

describe("verifyZohoIdToken", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256" };
  const getKey = createLocalJWKSet({ keys: [jwk] });
  const sign = (claims: JWTPayload, opts: { iss?: string; aud?: string; exp?: string } = {}) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(opts.iss ?? ISSUER)
      .setAudience(opts.aud ?? "client-id")
      .setIssuedAt()
      .setExpirationTime(opts.exp ?? "5m")
      .sign(privateKey);

  it("accepts a correctly signed token for this app", async () => {
    const payload = await verifyZohoIdToken(await sign({ sub: "s", email: "a@example.com" }), settings, getKey);
    expect(payload.sub).toBe("s");
  });

  it("rejects the wrong issuer, audience, an expired token or a foreign key", async () => {
    await expect(verifyZohoIdToken(await sign({ sub: "s" }, { iss: "https://accounts.zoho.com" }), settings, getKey)).rejects.toThrow();
    await expect(verifyZohoIdToken(await sign({ sub: "s" }, { aud: "other-client" }), settings, getKey)).rejects.toThrow();
    await expect(verifyZohoIdToken(await sign({ sub: "s" }, { exp: "-10m" }), settings, getKey)).rejects.toThrow();

    const other = await generateKeyPair("RS256");
    const forged = await new SignJWT({ sub: "s" })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(ISSUER)
      .setAudience("client-id")
      .setExpirationTime("5m")
      .sign(other.privateKey);
    await expect(verifyZohoIdToken(forged, settings, getKey)).rejects.toThrow();
  });
});
