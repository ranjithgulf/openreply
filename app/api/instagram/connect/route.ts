import { NextRequest, NextResponse } from "next/server";
import { canManageWorkspace, getCurrentWorkspaceContext } from "@/lib/workspace-access";
import { getBaseUrl, getMissingInstagramOAuthEnv } from "@/lib/env";
import {
  createOAuthState,
  getAuthorizationUrl,
  getFacebookAuthorizationUrl,
} from "@/lib/meta/oauth";
import {
  getDefaultMetaLoginMethod,
  parseMetaLoginMethod,
} from "@/lib/meta/login-method";

export async function GET(request: NextRequest) {
  const context = await getCurrentWorkspaceContext();
  if (!context) {
    return NextResponse.redirect(`${getBaseUrl()}/login`);
  }
  if (!canManageWorkspace(context.role)) {
    return NextResponse.redirect(`${getBaseUrl()}/settings?instagram=forbidden`);
  }

  // ?method=instagram|facebook (or "unified") picks a flow for one connect;
  // otherwise META_LOGIN_METHOD decides, and Instagram Login stays the
  // default so existing deployments behave exactly as before.
  const method =
    parseMetaLoginMethod(request.nextUrl.searchParams.get("method")) ??
    getDefaultMetaLoginMethod();

  // getAuthorizationUrl and createOAuthState call requireEnv, which throws.
  // Without this check an incomplete .env surfaces as a 500 on a plain <a>
  // navigation, which reads to the user as the button doing nothing at all.
  const missingEnv = getMissingInstagramOAuthEnv(method);
  if (missingEnv.length > 0) {
    return NextResponse.redirect(
      `${getBaseUrl()}/settings?instagram=misconfigured&missing=${encodeURIComponent(
        missingEnv.join(",")
      )}`
    );
  }

  // Both flows return to the same registered callback; the signed state
  // carries the method so the callback runs the matching token exchange.
  const redirectUri = `${getBaseUrl()}/api/instagram/callback`;
  const state = createOAuthState(context.workspaceId, method);

  return NextResponse.redirect(
    method === "facebook"
      ? getFacebookAuthorizationUrl(redirectUri, state)
      : getAuthorizationUrl(redirectUri, state)
  );
}
