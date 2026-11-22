/**
 * Zoho Directory single sign-on (OpenID Connect).
 *
 * Zoho Directory publishes per-application metadata at
 *   <AUTH_ZOHO_SSO_URL>/.well-known/openid-configuration
 * where the authorize/token/userinfo/keys endpoints live under the app's
 * `/sso` path but the `issuer` is an organization-specific Zoho Accounts URL
 * (https://accounts.zoho.<dc>/oauthapp/<org>), not accounts.zoho.com. Auth.js
 * would derive a wrong discovery URL from that issuer, so the endpoints are set
 * explicitly and the issuer is configured separately.
 *
 * Security model
 * - Auth.js validates state, PKCE (S256) and nonce, and the ID token's issuer,
 *   audience and expiry (oauth4webapi).
 * - `authorizeZohoSignIn` additionally verifies the ID token signature against
 *   the app's JWKS, requires `email_verified`, and requires the email to be on
 *   an explicit Zoho allowlist (fail closed when none is configured).
 * - Accounts are never linked by email alone: Auth.js refuses to attach a Zoho
 *   identity to an existing user unless that user is already signed in, and the
 *   sign-in callback additionally requires the Zoho email to match theirs.
 * - Zoho Directory publishes no end_session_endpoint, so signing out ends the
 *   OpenReply session only.
 */
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import type { OIDCConfig } from "next-auth/providers";

export const ZOHO_PROVIDER_ID = "zoho";

/** `id_token_signing_alg_values_supported` from the app's discovery document. */
const ID_TOKEN_ALGORITHMS = ["RS256", "RS384"];

export interface ZohoProfile extends Record<string, unknown> {
  sub: string;
  email?: string;
  email_verified?: boolean | string;
  name?: string;
  first_name?: string;
  last_name?: string;
  picture?: string;
}

export interface ZohoSettings {
  clientId: string;
  clientSecret: string;
  issuer: string;
  /** Application SSO base, e.g. https://directory.zoho.com/p/<org>/app/<app>/sso */
  ssoUrl: string;
}

type Env = Record<string, string | undefined>;

function httpsUrl(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "https:") return null;
    return trimmed.replace(/\/+$/, "");
  } catch {
    return null;
  }
}

/**
 * Returns the Zoho configuration, or null when any part is missing or not
 * HTTPS. A null result keeps the provider (and the login button) disabled.
 */
export function getZohoSettings(env: Env = process.env): ZohoSettings | null {
  const clientId = env.AUTH_ZOHO_ID?.trim();
  const clientSecret = env.AUTH_ZOHO_SECRET?.trim();
  const issuer = httpsUrl(env.AUTH_ZOHO_ISSUER);
  const ssoUrl = httpsUrl(env.AUTH_ZOHO_SSO_URL);
  if (!clientId || !clientSecret || !issuer || !ssoUrl) return null;
  return { clientId, clientSecret, issuer, ssoUrl };
}

export function isZohoSsoEnabled(env: Env = process.env): boolean {
  return getZohoSettings(env) !== null;
}

export function zohoProvider(settings: ZohoSettings): OIDCConfig<ZohoProfile> {
  return {
    id: ZOHO_PROVIDER_ID,
    name: "Zoho",
    type: "oidc",
    issuer: settings.issuer,
    clientId: settings.clientId,
    clientSecret: settings.clientSecret,
    authorization: {
      url: `${settings.ssoUrl}/authorize`,
      params: { scope: "openid email profile" },
    },
    token: `${settings.ssoUrl}/token`,
    userinfo: `${settings.ssoUrl}/userinfo`,
    checks: ["pkce", "state", "nonce"],
    client: { token_endpoint_auth_method: "client_secret_basic" },
    profile(profile) {
      const fullName = [profile.first_name, profile.last_name].filter(Boolean).join(" ");
      return {
        id: profile.sub,
        email: typeof profile.email === "string" ? profile.email.trim().toLowerCase() : null,
        name: profile.name ?? (fullName || null),
        image: profile.picture ?? null,
      };
    },
  };
}

function parseList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * ZOHO_ALLOWED_EMAILS (exact addresses) and ZOHO_ALLOWED_DOMAINS (exact
 * domains, no subdomain wildcard). With neither set, nobody may use Zoho.
 */
export function isZohoEmailAuthorized(email: string, env: Env = process.env): boolean {
  const emails = parseList(env.ZOHO_ALLOWED_EMAILS);
  const domains = parseList(env.ZOHO_ALLOWED_DOMAINS).map((d) => d.replace(/^@/, ""));
  if (emails.length === 0 && domains.length === 0) return false;

  const normalized = email.trim().toLowerCase();
  if (emails.includes(normalized)) return true;

  const at = normalized.lastIndexOf("@");
  if (at < 1 || at === normalized.length - 1) return false;
  return domains.includes(normalized.slice(at + 1));
}

export function isVerifiedEmailClaim(value: unknown): boolean {
  return value === true || value === "true";
}

let cachedJwks: { url: string; getKey: JWTVerifyGetKey } | null = null;

function remoteJwks(ssoUrl: string): JWTVerifyGetKey {
  const url = `${ssoUrl}/keys`;
  if (!cachedJwks || cachedJwks.url !== url) {
    cachedJwks = { url, getKey: createRemoteJWKSet(new URL(url)) };
  }
  return cachedJwks.getKey;
}

/** Verifies signature, issuer, audience and lifetime of a Zoho ID token. */
export async function verifyZohoIdToken(
  idToken: string,
  settings: ZohoSettings,
  getKey: JWTVerifyGetKey = remoteJwks(settings.ssoUrl),
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(idToken, getKey, {
    issuer: settings.issuer,
    audience: settings.clientId,
    algorithms: ID_TOKEN_ALGORITHMS,
    clockTolerance: 60,
  });
  return payload;
}

export type ZohoAuthorization =
  | { ok: true; email: string }
  | {
      ok: false;
      reason:
        | "not-configured"
        | "missing-id-token"
        | "invalid-id-token"
        | "subject-mismatch"
        | "email-missing"
        | "email-unverified"
        | "not-allowed";
    };

export interface ZohoSignInInput {
  account: { providerAccountId?: string; id_token?: string | null } | null | undefined;
}

export interface ZohoSignInDeps {
  settings?: ZohoSettings | null;
  verify?: (idToken: string, settings: ZohoSettings) => Promise<JWTPayload>;
  /** Instance-wide ALLOWED_EMAILS check, applied on top of the Zoho allowlist. */
  instanceAllows?: (email: string) => boolean;
  env?: Env;
}

/**
 * Decides whether a completed Zoho login may proceed. Identity claims are read
 * from the signature-verified ID token, never from unverified input.
 */
export async function authorizeZohoSignIn(
  { account }: ZohoSignInInput,
  deps: ZohoSignInDeps = {},
): Promise<ZohoAuthorization> {
  const env = deps.env ?? process.env;
  const settings = deps.settings === undefined ? getZohoSettings(env) : deps.settings;
  if (!settings) return { ok: false, reason: "not-configured" };

  const idToken = account?.id_token;
  if (!idToken) return { ok: false, reason: "missing-id-token" };

  let claims: JWTPayload;
  try {
    claims = await (deps.verify ?? verifyZohoIdToken)(idToken, settings);
  } catch {
    return { ok: false, reason: "invalid-id-token" };
  }

  if (!claims.sub || claims.sub !== account?.providerAccountId) {
    return { ok: false, reason: "subject-mismatch" };
  }

  const email = typeof claims.email === "string" ? claims.email.trim().toLowerCase() : "";
  if (!email) return { ok: false, reason: "email-missing" };
  if (!isVerifiedEmailClaim(claims.email_verified)) return { ok: false, reason: "email-unverified" };

  const instanceAllows = deps.instanceAllows ?? (() => true);
  if (!isZohoEmailAuthorized(email, env) || !instanceAllows(email)) {
    return { ok: false, reason: "not-allowed" };
  }

  return { ok: true, email };
}
