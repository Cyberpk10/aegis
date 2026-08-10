import { useState } from "react";
import type { FormEvent } from "react";
import AuthLayout from "./AuthLayout";
import { ErrorBanner, FormField, SubmitButton } from "./formFields";
import { useAuth } from "./AuthContext";
import { AuthError } from "../api/authClient";

interface OnboardingScreenProps {
  onSwitchToLogin: () => void;
}

const MIN_PASSWORD_LENGTH = 12;

export default function OnboardingScreen({ onSwitchToLogin }: OnboardingScreenProps) {
  const { signup } = useAuth();
  const [accountName, setAccountName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      await signup(accountName, email, password);
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Something went wrong while creating your account.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthLayout
      title="Create your Aegis account"
      subtitle="Set up your organization and admin login in under a minute."
      footer={
        <>
          Already have an account?{" "}
          <button
            type="button"
            onClick={onSwitchToLogin}
            className="font-medium text-brand-blue hover:underline"
          >
            Sign in
          </button>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {error && <ErrorBanner message={error} />}

        <FormField
          label="Organization name"
          type="text"
          required
          minLength={1}
          maxLength={200}
          value={accountName}
          onChange={(e) => setAccountName(e.target.value)}
          placeholder="Acme Corp"
        />

        <FormField
          label="Work email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <FormField
          label="Password"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD_LENGTH}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <p className="-mt-3 text-xs text-slate-500">At least {MIN_PASSWORD_LENGTH} characters.</p>

        <SubmitButton isLoading={isLoading}>Create account</SubmitButton>
      </form>
    </AuthLayout>
  );
}
