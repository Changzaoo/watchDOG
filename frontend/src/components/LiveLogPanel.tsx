import { useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';
import { ScanLog } from '@sentinelscope/shared';
import { cn } from '../lib/utils';

interface Props {
  logs: Array<Pick<ScanLog, 'level' | 'message'>>;
  maxHeight?: string;
}

export function LiveLogPanel({ logs, maxHeight = '200px' }: Props) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs.length]);

  return (
    <div className="card space-y-2">
      <div className="flex items-center gap-2 text-sm text-gray-400 font-medium">
        <Terminal className="w-4 h-4 text-cyan-400" />
        Log em tempo real
      </div>
      <div
        className="bg-dark-900 rounded-lg overflow-y-auto font-mono text-xs space-y-0.5 p-2"
        style={{ maxHeight }}
      >
        {logs.length === 0 && (
          <div className="text-gray-600 py-4 text-center">Aguardando logs...</div>
        )}
        {logs.map((log, i) => (
          <div
            key={i}
            className={cn(
              'log-entry break-words',
              log.level === 'error' ? 'log-error' :
              log.level === 'warn' ? 'log-warn' : 'log-info'
            )}
          >
            <span className="text-gray-600 mr-2">
              {log.level === 'error' ? '[ERR]' : log.level === 'warn' ? '[WARN]' : '[INFO]'}
            </span>
            {log.message}
          </div>
        ))}
        <div ref={endRef} />
      </div>
    </div>
  );
}
