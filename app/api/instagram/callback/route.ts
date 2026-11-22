import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db/client";
import { getBaseUrl } from "@/lib/env";
import { canConnectInstagramAccount } from "@/lib/instagram-accounts";
import {
  exchangeFacebookCodeForToken,
  getFacebookPagesWithInstagram,
  getFacebookTokenExpiry,
  getLongLivedFacebookUserToken,
  getLongLivedToken,
  getUserInfo,
  subscribeInstagramAccountToWebhooks,
} from "@/lib/meta/client";
import {
  encryptToken,
  exchangeCodeForToken,
  verifyOAuthState,
} from "@/lib/meta/oauth";
import { canManageWorkspace } from "@/lib/workspace-access";

interface ConnectedAccount {
  instagramId: string;
  username: string;
  name?: string;
  accessToken: string;
  tokenExpiresAt: Date | null;
}

/**
 * Subscribe webhooks and store one account. Returns false when the account
 * belongs to another workspace (or is a Zernio connection) and was left alone.
 */
async function saveMetaAccount(
  workspaceId: string,
  account: ConnectedAccount
): Promise<boolean> {
  const connection = await canConnectInstagramAccount({
    workspaceId,
    instagramId: account.instagramId,
  });
  if (!connection.allowed) return false;

  let webhookSubscribed = false;
  try {
    const subscription = await subscribeInstagramAccountToWebhooks(
      account.instagramId,
      account.accessToken
    );
    webhookSubscribed = Boolean(subscription.success);
  } catch (subscriptionError) {
    console.warn(
      "[Instagram Callback] Webhook subscription failed:",
      subscriptionError
    );
  }

  const data = {
    username: account.username,
    name: account.name,
    accessToken: encryptToken(account.accessToken),
    tokenExpiresAt: account.tokenExpiresAt,
    webhookSubscribed,
  };
  // instagramId is the professional account id in both flows, so reconnecting
  // an account through the other flow updates the same row and keeps its
  // campaigns, logs and history.
  const existing = await prisma.instagramAccount.findUnique({
    where: { instagramId: account.instagramId },
  });
  if (existing) {
    const updated = await prisma.instagramAccount.updateMany({
      where: { id: existing.id, workspaceId, provider: "META" },
      data,
    });
    return updated.count > 0;
  }
  await prisma.instagramAccount.create({
    data: {
      ...data,
      workspaceId,
      instagramId: account.instagramId,
      provider: "META",
    },
  });
  return true;
}

/** Instagram API with Instagram Login: one Instagram user token, one account. */
async function connectWithInstagramLogin(
  code: string,
  redirectUri: string
): Promise<ConnectedAccount[]> {
  const { accessToken: shortLivedToken } = await exchangeCodeForToken(
    code,
    redirectUri
  );
  const { accessToken: longLivedToken, expiresIn } =
    await getLongLivedToken(shortLivedToken);
  const userInfo = await getUserInfo(longLivedToken);
  // Webhooks and the messaging API key off the professional account ID
  // (user_id), not the app-scoped `id`. Store user_id so comment webhooks
  // can be matched back to this account. Fall back to id if user_id is
  // ever absent.
  return [
    {
      instagramId: userInfo.user_id ?? userInfo.id,
      username: userInfo.username,
      name: userInfo.name,
      accessToken: longLivedToken,
      tokenExpiresAt: new Date(Date.now() + expiresIn * 1000),
    },
  ];
}

/**
 * Facebook Login for Business ("Unified Login"): the login grants Pages, and
 * each Page with a linked Instagram professional account becomes one
 * connected account holding that Page's token.
 */
async function connectWithFacebookLogin(
  code: string,
  redirectUri: string
): Promise<ConnectedAccount[]> {
  const userToken = await getLongLivedFacebookUserToken(
    await exchangeFacebookCodeForToken(code, redirectUri)
  );
  const pages = await getFacebookPagesWithInstagram(userToken);
  if (pages.length === 0) {
    throw new Error(
      "No Facebook Page with a linked Instagram professional account was granted. Select the Page and its Instagram account during login."
    );
  }

  const accounts: ConnectedAccount[] = [];
  for (const page of pages) {
    accounts.push({
      instagramId: page.instagramId,
      username: page.instagramUsername ?? page.pageName ?? page.instagramId,
      name: page.instagramName,
      accessToken: page.pageAccessToken,
      // Page tokens from a long-lived user token never expire (null here,
      // which keeps them out of the refresh cron).
      tokenExpiresAt: await getFacebookTokenExpiry(page.pageAccessToken),
    });
  }
  return accounts;
}

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const error = request.nextUrl.searchParams.get("error");
  const state = verifyOAuthState(request.nextUrl.searchParams.get("state"));
  const baseUrl = getBaseUrl();

  if (error) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=denied`);
  }

  if (!code || !state) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=invalid`);
  }

  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.redirect(`${baseUrl}/login`);
  }

  const membership = await prisma.workspaceMember.findFirst({
    where: {
      workspaceId: state.workspaceId,
      userId: session.user.id,
    },
  });

  if (!membership || !canManageWorkspace(membership.role)) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=forbidden`);
  }

  try {
    const redirectUri = `${baseUrl}/api/instagram/callback`;
    const accounts =
      state.method === "facebook"
        ? await connectWithFacebookLogin(code, redirectUri)
        : await connectWithInstagramLogin(code, redirectUri);

    let saved = 0;
    for (const account of accounts) {
      if (await saveMetaAccount(state.workspaceId, account)) saved++;
    }
    if (saved === 0) {
      return NextResponse.redirect(
        `${baseUrl}/settings?instagram=already_connected`
      );
    }

    return NextResponse.redirect(`${baseUrl}/dashboard?connected=true`);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("[Instagram Callback] Error:", err);
    // The message is the only diagnostic a self-hoster gets for a failed
    // connect, so persist it alongside the other operational events rather
    // than leaving it in server logs they may not be able to reach.
    await prisma.operationalEvent
      .create({
        data: {
          source: "SYSTEM",
          level: "ERROR",
          workspaceId: state.workspaceId,
          message: "Instagram connection failed",
          payload: { reason: message, method: state.method ?? "instagram" },
        },
      })
      .catch(() => {});

    return NextResponse.redirect(
      `${baseUrl}/settings?instagram=failed&reason=${encodeURIComponent(
        message.slice(0, 200)
      )}`
    );
  }
}
