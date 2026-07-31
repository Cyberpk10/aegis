import { useRef, useState } from "react";

interface UploadFormProps {
  onSubmit: (file: File) => void;
  isLoading: boolean;
}

export default function UploadForm({ onSubmit, isLoading }: UploadFormProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(event.target.files?.[0] ?? null);
  };

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (selectedFile) {
      onSubmit(selectedFile);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4 sm:flex-row sm:items-center">
      <input
        ref={inputRef}
        type="file"
        accept=".eml"
        onChange={handleFileChange}
        className="block w-full flex-1 cursor-pointer rounded-lg border border-slate-300 bg-white text-sm text-slate-600 file:mr-4 file:cursor-pointer file:rounded-md file:border-0 file:bg-slate-800 file:px-4 file:py-2 file:text-sm file:font-medium file:text-white hover:file:bg-slate-700"
      />
      <button
        type="submit"
        disabled={!selectedFile || isLoading}
        className="whitespace-nowrap rounded-lg bg-indigo-600 px-5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
      >
        {isLoading ? "Analyzing…" : "Analyze Email"}
      </button>
    </form>
  );
}
