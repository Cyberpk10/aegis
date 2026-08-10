import type { ReactNode } from "react";
import AegisLogo from "../components/AegisLogo";

interface AuthLayoutProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}

export default function AuthLayout({ title, subtitle, children, footer }: AuthLayoutProps) {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <div className="relative hidden w-1/2 flex-col justify-between overflow-hidden bg-navy px-12 py-12 text-white lg:flex">
        <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-brand-blue/20 via-transparent to-brand-purple/20" />
        <div className="relative flex items-center gap-3">
          <AegisLogo className="h-9 w-9" />
          <span className="text-xl font-semibold tracking-tight">Aegis</span>
        </div>
        <div className="relative max-w-md">
          <h2 className="text-3xl font-semibold leading-tight text-white">
            Defensive security, built for the SOC.
          </h2>
          <p className="mt-4 text-slate-300">
            Phishing analysis, intrusion detection, and continuous control monitoring — in one
            platform.
          </p>
        </div>
        <p className="relative text-sm text-slate-400">&copy; {new Date().getFullYear()} Aegis</p>
      </div>

      <div className="flex w-full flex-1 flex-col justify-center px-6 py-12 sm:px-12 lg:w-1/2">
        <div className="mx-auto w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2 lg:hidden">
            <AegisLogo className="h-8 w-8" />
            <span className="text-lg font-semibold text-slate-900">Aegis</span>
          </div>

          <h1 className="text-2xl font-semibold text-slate-900">{title}</h1>
          {subtitle && <p className="mt-2 text-sm text-slate-600">{subtitle}</p>}

          <div className="mt-8">{children}</div>

          {footer && <div className="mt-6 text-sm text-slate-600">{footer}</div>}
        </div>
      </div>
    </div>
  );
}
