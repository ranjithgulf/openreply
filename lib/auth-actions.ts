"use server";

import { redirect } from "next/navigation";
import { auth, signIn, signOut } from "@/lib/auth";
import { prisma } from "@/lib/db/client";
import { ZOHO_PROVIDER_ID, isZohoSsoEnabled } from "@/lib/zoho-sso";

export interface SignInMethods {
  email: string | null;
  zohoEnabled: boolean;
  zohoLinked: boolean;
}

export async function getSignInMethods(): Promise<SignInMethods | null> {
  const session = await auth();
  const userId = session?.user?.id;
  if (!userId) return null;

  const zohoAccount = await prisma.account.findFirst({
    where: { userId, provider: ZOHO_PROVIDER_ID },
    select: { id: true },
  });

  return {
    email: session.user?.email ?? null,
    zohoEnabled: isZohoSsoEnabled(),
    zohoLinked: zohoAccount !== null,
  };
}

/**
 * Explicit account linking: only a signed-in user can attach a Zoho identity,
 * and the sign-in callback requires the Zoho email to match theirs.
 */
export async function linkZohoAccount(): Promise<void> {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  if (!isZohoSsoEnabled()) redirect("/settings?zoho=unavailable");
  await signIn(ZOHO_PROVIDER_ID, { redirectTo: "/settings?zoho=linked" });
}

/** Ends the OpenReply session. Zoho Directory offers no RP-initiated logout. */
export async function signOutOfOpenReply(): Promise<void> {
  await signOut({ redirectTo: "/login?signedOut=1" });
}
