import type { MessageChannel } from "../types/analysis";

const CHANNEL_STYLES: Record<MessageChannel, { label: string; classes: string }> = {
  email: { label: "Email", classes: "bg-slate-100 text-slate-700 border-slate-300" },
  slack: { label: "Slack", classes: "bg-purple-100 text-purple-800 border-purple-300" },
  teams: { label: "Teams", classes: "bg-blue-100 text-blue-800 border-blue-300" },
};

interface ChannelBadgeProps {
  channel: MessageChannel;
}

export default function ChannelBadge({ channel }: ChannelBadgeProps) {
  const style = CHANNEL_STYLES[channel];

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${style.classes}`}
    >
      {style.label}
    </span>
  );
}
