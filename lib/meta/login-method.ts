/**
 * Which Meta login flow connects an Instagram account.
 *
 * - "instagram": Instagram API with Instagram Login (Business Login for
 *   Instagram). Authorizes on www.instagram.com, yields an Instagram user token
 *   (IGAA…), and every call goes to graph.instagram.com. The original flow.
 * - "facebook": Instagram API with Facebook Login for Business, which Meta's
 *   dashboard labels "API setup with Unified Login". Authorizes on
 *   www.facebook.com with a configuration ID, yields a Facebook Page token
 *   (EAA…) for the Page linked to the Instagram account, and every call goes
 *   to graph.facebook.com.
 *
 * Both kinds of account live side by side in the same table. The stored token
 * itself says which host it belongs to (see isFacebookGraphToken), so no
 * schema change is needed and existing connections keep working untouched.
 */
export type MetaLoginMethod = "instagram" | "facebook";

export function parseMetaLoginMethod(
  value: string | null | undefined
): MetaLoginMethod | null {
  if (!value) return null;
  const normalized = value.trim().toLowerCase();
  if (normalized === "instagram") return "instagram";
  if (normalized === "facebook" || normalized === "unified") return "facebook";
  return null;
}

/** The flow the Connect button uses when the request does not name one. */
export function getDefaultMetaLoginMethod(): MetaLoginMethod {
  return parseMetaLoginMethod(process.env.META_LOGIN_METHOD) ?? "instagram";
}

/**
 * True for tokens issued through Facebook Login (user, Page and system-user
 * tokens all start with "EAA"). Instagram Login tokens start with "IG", so they
 * — and anything unrecognised — keep the original graph.instagram.com route.
 */
export function isFacebookGraphToken(accessToken: string): boolean {
  return accessToken.startsWith("EAA");
}
