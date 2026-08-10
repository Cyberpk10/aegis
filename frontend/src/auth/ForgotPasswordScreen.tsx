import { useState } from "react";
import type { FormEvent } from "react";
import AuthLayout from "./AuthLayout";
import { ErrorBanner, FormField, SubmitButton } from "./formFields";
import { AuthError, confirmPasswordReset, requestPasswordReset } from "../api/authClient";

interface ForgotPasswordScreenProps {
  onBackToLogin: () => void;
}

const MIN_PASSWORD_LENGTH = 12;

function extractToken(resetLink: string): string | null {
  try {
    return new URL(resetLink, window.location.origin).searchParams.get("token");
  } catch {
    return null;
  }
}

export default function ForgotPasswordScreen({ onBackToLogin }: ForgotPasswordScreenProps) {
  const [step, setStep] = useState<"request" | "confirm" | "done">("request");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [token, setToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleRequest = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      const response = await requestPasswordReset(email);
      setMessage(response.message);
      // Stubbed email delivery (no real inbox to check yet) — the link is handed back
      // directly, only ever when the account actually exists. See backend/app/api/routes/auth.py.
      if (response.reset_link) {
        const extracted = extractToken(response.reset_link);
        if (extracted) setToken(extracted);
      }
      setStep("confirm");
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Something went wrong. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleConfirm = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      await confirmPasswordReset(token, newPassword);
      setStep("done");
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Something went wrong. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  if (step === "done") {
    return (
      <AuthLayout title="Password updated" subtitle="You can now sign in with your new password.">
        <button
          type="button"
          onClick={onBackToLogin}
          className="flex w-full items-center justify-center rounded-lg bg-navy px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-navy-800"
        >
          Back to sign in
        </button>
      </AuthLayout>
    );
  }

  if (step === "confirm") {
    return (
      <AuthLayout
        title="Set a new password"
        subtitle={message ?? undefined}
        footer={
          <button
            type="button"
            onClick={onBackToLogin}
            className="font-medium text-brand-blue hover:underline"
          >
            Back to sign in
          </button>
        }
      >
        <form onSubmit={handleConfirm} className="flex flex-col gap-4">
          {error && <ErrorBanner message={error} />}

          <FormField
            label="Reset token"
            type="text"
            required
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste the token from your reset link"
          />

          <FormField
            label="New password"
            type="password"
            autoComplete="new-password"
            required
            minLength={MIN_PASSWORD_LENGTH}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <p className="-mt-3 text-xs text-slate-500">At least {MIN_PASSWORD_LENGTH} characters.</p>

          <SubmitButton isLoading={isLoading}>Update password</SubmitButton>
        </form>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title="Reset your password"
      subtitle="Enter your email and we'll generate a reset link."
      footer={
        <button
          type="button"
          onClick={onBackToLogin}
          className="font-medium text-brand-blue hover:underline"
        >
          Back to sign in
        </button>
      }
    >
      <form onSubmit={handleRequest} className="flex flex-col gap-4">
        {error && <ErrorBanner message={error} />}

        <FormField
          label="Email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <SubmitButton isLoading={isLoading}>Send reset link</SubmitButton>
      </form>
    </AuthLayout>
  );
}
