import { useAuth } from "../../auth/AuthContext";
import ForwardingAddressCard from "./ForwardingAddressCard";

export default function SettingsView() {
  const { user } = useAuth();

  if (!user) return null;

  return (
    <div className="flex flex-col gap-6">
      <ForwardingAddressCard forwardingAddress={user.forwarding_address} />
    </div>
  );
}
