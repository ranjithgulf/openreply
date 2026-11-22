"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useI18n } from "@/lib/i18n/provider";
import {
  getSignInMethods,
  linkZohoAccount,
  signOutOfOpenReply,
  type SignInMethods,
} from "@/lib/auth-actions";

type ZohoNotice = "linked" | "email-mismatch" | "already-linked" | "denied" | "unavailable";

const NOTICES: ZohoNotice[] = ["linked", "email-mismatch", "already-linked", "denied", "unavailable"];

export function SignInMethodsSection() {
  const { t } = useI18n();
  const [methods, setMethods] = useState<SignInMethods | null>(null);
  const zohoParam = useSearchParams().get("zoho");
  const notice = zohoParam && (NOTICES as string[]).includes(zohoParam) ? (zohoParam as ZohoNotice) : null;

  useEffect(() => {
    getSignInMethods().then(setMethods).catch(() => setMethods(null));
  }, []);

  const noticeText: Record<ZohoNotice, string> = {
    linked: t("Zoho account linked."),
    "email-mismatch": t("The Zoho account email must match your OpenReply email."),
    "already-linked": t("That Zoho account is linked to another OpenReply user."),
    denied: t("Zoho sign-in was not allowed for this account."),
    unavailable: t("Sign-in failed. Please try again."),
  };

  return (
    <section className="panel rounded p-4 sm:p-6 space-y-4">
      <h2 className="text-base font-semibold">{t("Account")}</h2>

      {methods?.email && (
        <p className="text-sm text-muted">{t("Signed in as {email}", { email: methods.email })}</p>
      )}

      {notice && (
        <p
          role="status"
          className={`text-sm ${notice === "linked" ? "text-emerald-400" : "text-amber-400"}`}
        >
          {noticeText[notice]}
        </p>
      )}

      {methods?.zohoEnabled && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
          <div>
            <p className="text-sm font-medium text-foreground">{t("Zoho SSO")}</p>
            <p className="text-xs text-muted">{methods.zohoLinked ? t("Linked") : t("Not linked")}</p>
          </div>
          {!methods.zohoLinked && (
            <form action={linkZohoAccount}>
              <button
                type="submit"
                className="rounded border border-border px-4 py-2 text-sm font-medium text-foreground hover:border-accent/40"
              >
                {t("Link Zoho account")}
              </button>
            </form>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
        <p className="text-xs text-muted">
          {methods?.zohoEnabled ? t("Signing out of OpenReply does not sign you out of Zoho.") : null}
        </p>
        <form action={signOutOfOpenReply}>
          <button
            type="submit"
            className="rounded border border-border px-4 py-2 text-sm font-medium text-foreground hover:border-accent/40"
          >
            {t("Sign out")}
          </button>
        </form>
      </div>
    </section>
  );
}
