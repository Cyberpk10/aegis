import { useState } from "react";
import CaseDetail from "./CaseDetail";
import CasesTable from "./CasesTable";

export default function CasesView() {
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);

  if (selectedCaseId) {
    return (
      <CaseDetail
        caseId={selectedCaseId}
        onBack={() => setSelectedCaseId(null)}
        onDeleted={() => {
          setSelectedCaseId(null);
          setRefreshToken((token) => token + 1);
        }}
      />
    );
  }

  return <CasesTable onSelectCase={setSelectedCaseId} refreshToken={refreshToken} />;
}
