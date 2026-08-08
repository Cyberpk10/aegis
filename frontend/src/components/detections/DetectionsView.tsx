import { useState } from "react";
import IncidentDetail from "./IncidentDetail";
import IncidentsTable from "./IncidentsTable";

export default function DetectionsView() {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);

  if (selectedIncidentId) {
    return (
      <IncidentDetail
        incidentId={selectedIncidentId}
        onBack={() => setSelectedIncidentId(null)}
        onDeleted={() => {
          setSelectedIncidentId(null);
          setRefreshToken((token) => token + 1);
        }}
      />
    );
  }

  return <IncidentsTable onSelectIncident={setSelectedIncidentId} refreshToken={refreshToken} />;
}
