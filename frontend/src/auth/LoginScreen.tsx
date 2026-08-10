import { useState } from "react";
import type { FormEvent } from "react";
import AuthLayout from "./AuthLayout";
import { ErrorBanner, FormField, SubmitButton } from "./formFields";
import { useAuth } from "./AuthContext";
import { AuthError } from "../api/authClient";

interface LoginScreenProps {
  onSwitchToSignup: () => void;
  onForgotPassword: () => void;
}

export default function LoginScreen({ onSwitchToSignup, onForgotPassword }: LoginScreenProps) {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Something went wrong while signing in.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthLayout
      title="Sign in to Aegis"
      subtitle="Enter your credentials to access your account."
      footer={
        <>
          Don&apos;t have an account?{" "}
          <button
            type="button"
            onClick={onSwitchToSignup}
            className="font-medium text-brand-blue hover:underline"
          >
            Create one
          </button>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {error && <ErrorBanner message={error} />}

        <FormField
          label="Email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <div>
          <FormField
            label="Password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button
            type="button"
            onClick={onForgotPassword}
            className="mt-1.5 text-sm font-medium text-brand-blue hover:underline"
          >
            Forgot password?
          </button>
        </div>

        <SubmitButton isLoading={isLoading}>Sign in</SubmitButton>

        <div className="relative py-1 text-center text-xs text-slate-400">
          <span className="relative bg-slate-50 px-2">or</span>
          <div className="absolute left-0 right-0 top-1/2 -z-10 border-t border-slate-200" />
        </div>

        <div className="group relative">
          <button
            type="button"
            disabled
            className="flex w-full cursor-not-allowed items-center justify-center rounded-lg border border-slate-300 px-4 py-2.5 text-sm font-semibold text-slate-400"
          >
            Continue with SSO
          </button>
          <div className="pointer-events-none absolute -top-9 left-1/2 -translate-x-1/2 whitespace-nowrap rounded-md bg-slate-900 px-2 py-1 text-xs text-white opacity-0 transition group-hover:opacity-100">
            Coming soon
          </div>
        </div>
      </form>
    </AuthLayout>
  );
}
