import AuthLayout from "./AuthLayout";
import ForwardingAddressCard from "../components/settings/ForwardingAddressCard";
import { useAuth } from "./AuthContext";

interface WelcomeForwardingScreenProps {
  onContinue: () => void;
}

export default function WelcomeForwardingScreen({ onContinue }: WelcomeForwardingScreenProps) {
  const { user } = useAuth();
  if (!user) return null;

  return (
    <AuthLayout
      title="You're all set"
      subtitle="One last thing before your dashboard — here's how your team reports phishing."
    >
      <ForwardingAddressCard forwardingAddress={user.forwarding_address} />
      <button
        type="button"
        onClick={onContinue}
        className="mt-6 flex w-full items-center justify-center rounded-lg bg-navy px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-navy-800"
      >
        Continue to dashboard
      </button>
      <p className="mt-3 text-center text-xs text-slate-500">
        You can always find this address again under Settings.
      </p>
    </AuthLayout>
  );
}
