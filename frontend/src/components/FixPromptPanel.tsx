import { useMemo, useState } from 'react';
import { CheckCircle, Copy, Download, Wand2 } from 'lucide-react';
import { Finding, Scan } from '@sentinelscope/shared';
import { generateAggregateFixPrompt, getFixableFindings } from '../lib/fixPrompt';

interface Props {
  scan: Scan;
  findings: Finding[];
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function FixPromptPanel({ scan, findings }: Props) {
  const [copied, setCopied] = useState(false);
  const prompt = useMemo(() => generateAggregateFixPrompt(scan, findings), [scan, findings]);
  const fixableCount = getFixableFindings(findings).length;

  const copyPrompt = async () => {
    await navigator.clipboard.writeText(prompt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadPrompt = () => {
    const safeName = scan.projectName.replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '') || 'scan';
    downloadText(`${safeName}-prompt-correcao.txt`, prompt);
  };

  return (
    <div className="card space-y-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-semibold text-gray-200">
            <Wand2 className="w-4 h-4 text-cyan-400" />
            Prompt para corrigir vulnerabilidades
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Gerado a partir de {fixableCount || findings.length} achados para orientar correcoes no codigo, headers e configuracoes.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:flex sm:items-center">
          <button onClick={copyPrompt} className="btn-secondary touch-row text-xs flex items-center justify-center gap-1.5">
            {copied ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copiado!' : 'Copiar prompt'}
          </button>
          <button onClick={downloadPrompt} className="btn-secondary touch-row text-xs flex items-center justify-center gap-1.5">
            <Download className="w-3.5 h-3.5" />
            Baixar .txt
          </button>
        </div>
      </div>

      <pre className="font-mono text-xs bg-dark-900 rounded-lg p-3 sm:p-4 text-cyan-100 overflow-x-auto whitespace-pre-wrap max-h-96">
        {prompt}
      </pre>
    </div>
  );
}
