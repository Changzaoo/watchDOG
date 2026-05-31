import { useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  FileCode,
  Link,
  Copy,
  CheckCircle,
  XCircle,
  Info,
  Save,
} from 'lucide-react';
import { Finding } from '@sentinelscope/shared';
import { SeverityBadge } from './SeverityBadge';
import { statusLabel } from '../lib/utils';
import { api } from '../lib/api';
import { useAppStore } from '../store/useAppStore';

interface Props {
  finding: Finding;
}

export function FindingCard({ finding }: Props) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [note, setNote] = useState(finding.userNote || '');
  const [savingNote, setSavingNote] = useState(false);
  const updateStatus = useAppStore(s => s.updateFindingStatus);
  const updateNote = useAppStore(s => s.updateFindingNote);

  const handleStatus = async (status: string) => {
    await api.updateFindingStatus(finding.id, status);
    updateStatus(finding.id, status);
  };

  const copyRemediation = () => {
    navigator.clipboard.writeText(finding.safeExample || finding.remediation);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copyFixPrompt = () => {
    navigator.clipboard.writeText(finding.fixPrompt || finding.remediation);
    setCopiedPrompt(true);
    setTimeout(() => setCopiedPrompt(false), 2000);
  };

  const saveNote = async () => {
    setSavingNote(true);
    try {
      const updated = await api.updateFindingNote(finding.id, note);
      updateNote(finding.id, updated.userNote || '');
    } finally {
      setSavingNote(false);
    }
  };

  const confidenceLabel = {
    high: 'Alta',
    medium: 'Media',
    low: 'Baixa',
  }[finding.confidence || 'medium'];

  return (
    <div className="overflow-hidden rounded-lg border border-dark-800 bg-dark-850 transition-colors hover:border-dark-700">
      <div
        className="flex cursor-pointer items-start gap-3 p-3 sm:p-4"
        onClick={() => setOpen(!open)}
      >
        <div className="mt-0.5 flex-shrink-0">
          {open ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs text-gray-500 bg-dark-800 px-2 py-0.5 rounded">{finding.category}</span>
            <span className="text-xs font-mono text-gray-600">{finding.ruleId}</span>
            <span className="text-xs text-cyan-300 bg-cyan-900/20 px-2 py-0.5 rounded">
              Confianca {confidenceLabel}
            </span>
            {finding.occurrences > 1 && (
              <span className="text-xs text-orange-300 bg-orange-900/20 px-2 py-0.5 rounded">
                {finding.occurrences} ocorrencias
              </span>
            )}
            {finding.status !== 'open' && (
              <span className="text-xs px-2 py-0.5 rounded bg-dark-800 text-gray-400">
                {statusLabel(finding.status)}
              </span>
            )}
          </div>
          <div className="mt-1 line-clamp-2 font-medium text-gray-200 sm:truncate">{finding.title}</div>
          <div className="mt-0.5 text-xs text-gray-500 flex items-center gap-2 flex-wrap">
            {finding.filePath && (
              <span className="flex items-center gap-1">
                <FileCode className="w-3 h-3" />
                <span className="max-w-[14rem] truncate font-mono sm:max-w-xs">
                  {finding.filePath.split(/[/\\]/).slice(-2).join('/')}
                  {finding.line ? `:${finding.line}` : ''}
                </span>
              </span>
            )}
            {finding.url && (
              <span className="flex items-center gap-1">
                <Link className="w-3 h-3" />
                <span className="max-w-[14rem] truncate sm:max-w-xs">{finding.url}</span>
              </span>
            )}
          </div>
        </div>
      </div>

      {open && (
        <div className="border-t border-dark-800 p-3 sm:p-4 space-y-4 animate-fade-in">
          {finding.evidenceMasked && (
            <div>
              <div className="text-xs text-gray-500 mb-1">Evidencia mascarada</div>
              <pre className="font-mono text-xs bg-dark-900 rounded-lg p-3 text-red-400 overflow-x-auto">
                {finding.evidenceMasked}
              </pre>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <div className="text-xs text-gray-500 mb-1">Descricao</div>
              <p className="text-sm text-gray-300">{finding.description}</p>
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1 flex items-center gap-1">
                <Info className="w-3 h-3" /> Impacto
              </div>
              <p className="text-sm text-orange-400">{finding.impact}</p>
            </div>
          </div>

          {finding.attackScenarioDefensive && (
            <div>
              <div className="text-xs text-gray-500 mb-1">Cenario defensivo</div>
              <p className="text-sm text-gray-300">{finding.attackScenarioDefensive}</p>
            </div>
          )}

          <div>
            <div className="text-xs text-gray-500 mb-1">Como corrigir</div>
            <p className="text-sm text-gray-300">{finding.remediation}</p>
          </div>

          {finding.safeExample && (
            <div>
              <div className="text-xs text-gray-500 mb-1">Exemplo seguro</div>
              <pre className="font-mono text-xs bg-dark-900 rounded-lg p-3 text-green-400 overflow-x-auto whitespace-pre-wrap">
                {finding.safeExample}
              </pre>
            </div>
          )}

          {finding.testSuggestion && (
            <div>
              <div className="text-xs text-gray-500 mb-1">Teste sugerido</div>
              <p className="text-sm text-gray-300">{finding.testSuggestion}</p>
            </div>
          )}

          {finding.fixPrompt && (
            <div>
              <div className="flex flex-col gap-2 mb-1 sm:flex-row sm:items-center sm:justify-between">
                <div className="text-xs text-gray-500">Prompt de correcao</div>
                <button onClick={copyFixPrompt} className="btn-secondary touch-row text-xs flex items-center justify-center gap-1.5 py-1">
                  {copiedPrompt ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedPrompt ? 'Copiado!' : 'Copiar prompt'}
                </button>
              </div>
              <pre className="font-mono text-xs bg-dark-900 rounded-lg p-3 text-cyan-200 overflow-x-auto whitespace-pre-wrap max-h-56">
                {finding.fixPrompt}
              </pre>
            </div>
          )}

          {finding.reference && (
            <div className="text-xs text-gray-600">
              Referencia: {finding.reference}
            </div>
          )}

          <div>
            <div className="text-xs text-gray-500 mb-1">Nota do usuario</div>
            <div className="flex flex-col gap-2 sm:flex-row">
              <textarea
                className="input min-h-20 resize-y text-sm"
                value={note}
                onChange={e => setNote(e.target.value)}
                placeholder="Observacoes, falso positivo explicado, link do PR de correcao..."
                maxLength={1000}
              />
              <button
                onClick={saveNote}
                disabled={savingNote}
                className="btn-secondary touch-row flex items-center justify-center p-2 disabled:opacity-50 sm:self-start"
                title="Salvar nota"
              >
                <Save className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-2 pt-2 border-t border-dark-800 sm:flex sm:flex-wrap sm:items-center">
            <button onClick={copyRemediation} className="btn-secondary touch-row text-xs flex items-center justify-center gap-1.5">
              {copied ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copiado!' : 'Copiar correcao'}
            </button>
            {finding.status === 'open' && (
              <>
                <button
                  onClick={() => handleStatus('fixed')}
                  className="btn-primary touch-row text-xs flex items-center justify-center gap-1.5"
                >
                  <CheckCircle className="w-3.5 h-3.5" /> Marcar corrigido
                </button>
                <button
                  onClick={() => handleStatus('false_positive')}
                  className="btn-secondary touch-row text-xs flex items-center justify-center gap-1.5"
                >
                  <XCircle className="w-3.5 h-3.5" /> Falso positivo
                </button>
                <button
                  onClick={() => handleStatus('ignored')}
                  className="btn-secondary touch-row text-xs"
                >
                  Ignorar
                </button>
              </>
            )}
            {finding.status !== 'open' && (
              <button
                onClick={() => handleStatus('open')}
                className="btn-secondary touch-row text-xs"
              >
                Reabrir
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
