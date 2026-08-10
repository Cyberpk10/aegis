import ControlGrid from "./ControlGrid";
import DriftAlertFeed from "./DriftAlertFeed";

export default function ControlMonitoringView() {
  return (
    <div className="flex flex-col gap-6">
      <ControlGrid />
      <DriftAlertFeed />
    </div>
  );
}
