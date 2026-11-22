import NextAuth, { type NextAuthConfig } from "next-auth";
import Nodemailer from "next-auth/providers/nodemailer";
import Resend from "next-auth/providers/resend";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { cookies } from "next/headers";
import { prisma } from "@/lib/db/client";
import { ensureWorkspaceForUser, getPrimaryWorkspace } from "@/lib/workspace";
import { isEmailAllowedToSignIn } from "@/lib/env";
import {
  ZOHO_PROVIDER_ID,
  authorizeZohoSignIn,
  getZohoSettings,
  zohoProvider,
} from "@/lib/zoho-sso";

type AdapterPrismaClient = Parameters<typeof PrismaAdapter>[0];

const emailFrom = process.env.EMAIL_FROM ?? "OpenReply <login@example.com>";
// Setting EMAIL_SERVER switches magic links to your own SMTP server, for
// self-hosters who do not want a third-party mail service. Resend stays the
// default, so an existing deployment is unaffected.
const smtpServer = process.env.EMAIL_SERVER;

/**
 * Provider id the login form has to sign in with. It differs per transport,
 * so it is derived here rather than hardcoded at the call site.
 */
export const EMAIL_PROVIDER_ID = smtpServer ? "nodemailer" : "resend";

// Zoho Directory SSO is added only when fully configured (see lib/zoho-sso.ts),
// so deployments without the AUTH_ZOHO_* variables behave exactly as before.
const zohoSettings = getZohoSettings();

const SESSION_COOKIES = ["__Secure-authjs.session-token", "authjs.session-token"];

/** The user of the current database session, if the browser has one. */
async function getSignedInUser(): Promise<{ id: string; email: string | null } | null> {
  const cookieStore = await cookies();
  for (const name of SESSION_COOKIES) {
    const sessionToken = cookieStore.get(name)?.value;
    if (!sessionToken) continue;
    const session = await prisma.session.findUnique({
      where: { sessionToken },
      select: { expires: true, user: { select: { id: true, email: true } } },
    });
    if (session && session.expires > new Date()) return session.user;
  }
  return null;
}

export const authConfig = {
  adapter: PrismaAdapter(prisma as unknown as AdapterPrismaClient),
  providers: [
    smtpServer
      ? Nodemailer({ server: smtpServer, from: emailFrom })
      : Resend({
          apiKey: process.env.RESEND_API_KEY ?? "missing-resend-api-key",
          from: emailFrom,
        }),
    ...(zohoSettings ? [zohoProvider(zohoSettings)] : []),
  ],
  callbacks: {
    // Runs before the magic link is sent, so a blocked address never receives
    // one, and again when the link is verified.
    async signIn({ user, account }) {
      if (account?.provider !== ZOHO_PROVIDER_ID) {
        return isEmailAllowedToSignIn(user?.email);
      }

      const signedInUser = await getSignedInUser();
      const result = await authorizeZohoSignIn(
        { account },
        { settings: zohoSettings, instanceAllows: isEmailAllowedToSignIn },
      );
      if (!result.ok) {
        console.warn(`[auth] Zoho sign-in rejected: ${result.reason}`);
        return signedInUser ? "/settings?zoho=denied" : "/login?error=ZohoAccessDenied";
      }

      // Linking from Settings: Auth.js attaches the Zoho identity to the
      // signed-in user. Require the same verified email, and never move an
      // identity that already belongs to someone else.
      if (signedInUser) {
        if (signedInUser.email?.toLowerCase() !== result.email) {
          return "/settings?zoho=email-mismatch";
        }
        const linked = await prisma.account.findUnique({
          where: {
            provider_providerAccountId: {
              provider: ZOHO_PROVIDER_ID,
              providerAccountId: account.providerAccountId,
            },
          },
          select: { userId: true },
        });
        if (linked && linked.userId !== signedInUser.id) {
          return "/settings?zoho=already-linked";
        }
      }
      return true;
    },
    async session({ session, user }) {
      if (session.user) {
        session.user.id = user.id;
      }
      return session;
    },
  },
  events: {
    async createUser({ user }) {
      if (user.id) {
        await ensureWorkspaceForUser(user.id, user.email);
      }
    },
  },
  pages: {
    signIn: "/login",
    verifyRequest: "/verify-request",
    // OAuth errors (e.g. OAuthAccountNotLinked) render on the login page
    // instead of the bare Auth.js error page.
    error: "/login",
  },
  session: {
    strategy: "database",
  },
  trustHost: true,
  secret: process.env.NEXTAUTH_SECRET,
} satisfies NextAuthConfig;

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig);

export async function getCurrentUserId(): Promise<string | null> {
  const session = await auth();
  return session?.user?.id ?? null;
}

export async function getCurrentWorkspaceId(): Promise<string | null> {
  const userId = await getCurrentUserId();
  if (!userId) return null;

  const workspace = await getPrimaryWorkspace(userId);
  if (workspace) return workspace.id;

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { email: true },
  });

  const createdWorkspace = await ensureWorkspaceForUser(userId, user?.email);
  return createdWorkspace.id;
}
