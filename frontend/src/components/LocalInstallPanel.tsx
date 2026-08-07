import { useState } from 'react';
import { CheckCircle2, Clipboard, Download, MonitorUp, Terminal, X } from 'lucide-react';

const INSTALLER_PATH = '/install-watchdog-local.ps1';
const INSTALL_COMMAND = 'powershell -ExecutionPolicy Bypass -Command "iwr https://watchdog-chi.vercel.app/install-watchdog-local.ps1 -OutFile $env:TEMP\\install-watchdog-local.ps1; & $env:TEMP\\install-watchdog-local.ps1"';

export function LocalInstallPanel() {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  function downloadInstaller() {
    setOpen(true);
    const link = document.createElement('a');
    link.href = INSTALLER_PATH;
    link.download = 'install-watchdog-local.ps1';
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  async function copyCommand() {
    await navigator.clipboard.writeText(INSTALL_COMMAND);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <>
      <div className="card border-cyan-900/40 bg-cyan-950/10">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-900/40 border border-cyan-800/50 flex items-center justify-center flex-shrink-0">
              <MonitorUp className="w-5 h-5 text-cyan-300" />
            </div>
            <div>
              <div className="font-semibold text-gray-200">Instalar watchDOG no computador</div>
              <p className="text-sm text-gray-500 mt-1">
                A versao web analisa URLs. Para auditar pastas da sua maquina, rode a versao em localhost.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={downloadInstaller}
            className="btn-primary flex items-center justify-center gap-2 whitespace-nowrap"
          >
            <Download className="w-4 h-4" />
            Baixar instalador
          </button>
        </div>
      </div>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-2xl rounded-xl border border-dark-700 bg-dark-850 p-5 shadow-2xl">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 text-lg font-semibold text-white">
                  <Terminal className="w-5 h-5 text-cyan-300" />
                  Instalacao local
                </div>
                <p className="text-sm text-gray-500 mt-1">
                  Execute o instalador baixado ou cole o comando abaixo no PowerShell.
                </p>
              </div>
              <button type="button" onClick={() => setOpen(false)} className="btn-secondary p-2">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-5">
              {[
                'Prepara Node, Git e dependencias',
                'Configura o backend local',
                'Abre http://localhost:5173',
              ].map(step => (
                <div key={step} className="rounded-lg border border-dark-800 bg-dark-900 p-3 text-sm text-gray-300">
                  <CheckCircle2 className="w-4 h-4 text-green-400 mb-2" />
                  {step}
                </div>
              ))}
            </div>

            <div className="mt-5 rounded-lg border border-dark-800 bg-dark-900 p-3">
              <div className="flex items-center justify-between gap-3 mb-2">
                <span className="text-xs font-medium uppercase tracking-wide text-gray-500">Comando rapido</span>
                <button type="button" onClick={copyCommand} className="btn-secondary py-1.5 px-3 text-xs flex items-center gap-2">
                  <Clipboard className="w-3.5 h-3.5" />
                  {copied ? 'Copiado' : 'Copiar'}
                </button>
              </div>
              <code className="block whitespace-pre-wrap break-all text-xs text-cyan-200">{INSTALL_COMMAND}</code>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
