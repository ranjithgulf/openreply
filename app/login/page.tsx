import { EMAIL_PROVIDER_ID, signIn } from "@/lib/auth";
import { getI18n } from "@/lib/i18n/server";
import { getCampaignTemplate } from "@/lib/templates/campaign-templates";
import { DemoNotice } from "@/components/demo-notice";
import { isPublicDemoHost } from "@/lib/env";
import { ZOHO_PROVIDER_ID, isZohoSsoEnabled } from "@/lib/zoho-sso";

const GITHUB_URL = "https://github.com/diwenne/openreply";
const SETUP_DOCS_URL = `${GITHUB_URL}/blob/main/docs/setup.md`;

export async function generateMetadata() {
  const { t } = await getI18n();
  return {
    title: t("Login - OpenReply"),
    description: t("Sign in to manage Instagram comment-to-DM campaigns."),
  };
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{
    checkEmail?: string;
    callbackUrl?: string;
    template?: string;
    error?: string;
    signedOut?: string;
  }>;
}) {
  const { t } = await getI18n();
  if (await isPublicDemoHost()) {
    return (
      <div className="min-h-screen flex items-center justify-center px-6">
        <div className="w-full max-w-md text-center">
          <h1 className="text-2xl font-semibold text-foreground">
            OpenReply
          </h1>
          <div className="panel rounded p-8 mt-8 shadow-black/40">
            <h2 className="text-lg font-semibold text-foreground">
              {t("Sign-in is off on this demo")}
            </h2>
            <p className="mt-3 text-sm leading-relaxed text-muted">
              {t("This is the public demo — it doesn’t create real accounts or send DMs. To use OpenReply for real, clone it and run your own instance with your own Meta app and domain.")}
            </p>
            <a
              href={SETUP_DOCS_URL}
              target="_blank"
              rel="noreferrer"
              className="mt-6 inline-flex w-full items-center justify-center gap-2 rounded bg-accent px-6 py-3.5 text-sm font-semibold text-white shadow-indigo-500/25 transition-all hover:shadow-indigo-500/30"
            >
              {t("Clone it yourself")} <span aria-hidden="true">↗</span>
            </a>
          </div>
        </div>
      </div>
    );
  }

  const params = await searchParams;
  const checkEmail = params.checkEmail === "1";
  const selectedTemplate = getCampaignTemplate(params.template);
  const templateCallbackUrl = selectedTemplate
    ? `/campaigns/new?template=${selectedTemplate.slug}`
    : null;
  const callbackUrl = params.callbackUrl ?? templateCallbackUrl ?? "/dashboard";

  async function sendMagicLink(formData: FormData) {
    "use server";
    await signIn(EMAIL_PROVIDER_ID, {
      email: String(formData.get("email") ?? ""),
      redirectTo: callbackUrl,
    });
  }

  const zohoEnabled = isZohoSsoEnabled();

  async function signInWithZoho() {
    "use server";
    await signIn(ZOHO_PROVIDER_ID, { redirectTo: callbackUrl });
  }

  // `error` comes from Auth.js (pages.error) or from the Zoho sign-in callback.
  const errorMessage = params.error
    ? params.error === "ZohoAccessDenied" || params.error === "AccessDenied"
      ? t("Zoho sign-in was not allowed. Ask your administrator to grant you access to OpenReply.")
      : params.error === "OAuthAccountNotLinked"
        ? t("An OpenReply account already uses this email. Sign in with a magic link first, then link Zoho in Settings.")
        : params.error === "Verification"
          ? t("This sign-in link is invalid or has expired.")
          : t("Sign-in failed. Please try again.")
    : null;
  const signedOut = params.signedOut === "1";

  return (
    <div className="min-h-screen flex items-center justify-center px-6">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-semibold text-foreground">
            OpenReply
          </h1>
          <p className="text-muted text-sm leading-relaxed mt-2">
            {selectedTemplate
              ? t("Sign in to use the {name} template.", { name: selectedTemplate.title })
              : t("Sign in by email, then connect your Instagram professional account.")}
          </p>
        </div>

        <DemoNotice variant="panel" />

        <div className="panel rounded p-8 shadow-black/40">
          {errorMessage && !checkEmail && (
            <p role="alert" className="mb-5 border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
              {errorMessage}
            </p>
          )}
          {signedOut && !errorMessage && !checkEmail && (
            <p role="status" className="mb-5 border border-border bg-surface p-3 text-sm text-muted">
              {zohoEnabled
                ? t("You are signed out of OpenReply. Your Zoho session may still be active.")
                : t("You are signed out of OpenReply.")}
            </p>
          )}
          {selectedTemplate && !checkEmail && (
            <div className="mb-5 border border-accent/20 bg-accent/10 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-accent">
                {t("Template selected")}
              </p>
              <p className="mt-2 text-sm font-semibold text-foreground">
                {selectedTemplate.title}
              </p>
            </div>
          )}

          {checkEmail ? (
            <div className="text-center py-4">
              <h2 className="text-lg font-semibold mb-2">{t("Check your email")}</h2>
              <p className="text-sm text-muted">
                {t("We sent you a secure sign-in link. Open it on this device to continue.")}
              </p>
            </div>
          ) : (
            <>
            {zohoEnabled && (
              <>
                <form action={signInWithZoho}>
                  <button
                    type="submit"
                    className="w-full inline-flex items-center justify-center gap-2 rounded border border-border bg-surface px-6 py-3.5 text-sm font-semibold text-foreground transition-colors hover:border-accent/40"
                  >
                    {t("Sign in with Zoho")}
                  </button>
                </form>
                <div className="my-5 flex items-center gap-3 text-xs uppercase tracking-wide text-muted">
                  <span className="h-px flex-1 bg-border" />
                  {t("or")}
                  <span className="h-px flex-1 bg-border" />
                </div>
              </>
            )}
            <form action={sendMagicLink} className="space-y-5">
              <div className="space-y-2">
                <label
                  htmlFor="email"
                  className="block text-sm font-medium text-foreground"
                >
                  {t("Work email")}
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  required
                  autoComplete="email"
                  placeholder="you@company.com"
                  className="w-full px-4 py-3 rounded bg-surface border border-border text-sm text-foreground placeholder:text-zinc-500 focus:border-accent/40 focus:outline-none transition-colors"
                />
              </div>

              <button
                type="submit"
                className="w-full inline-flex items-center justify-center gap-2 rounded bg-accent px-6 py-3.5 text-sm font-semibold text-white shadow-indigo-500/25 transition-all hover:shadow-indigo-500/30"
              >
                {t("Email me a magic link")}
              </button>
            </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
