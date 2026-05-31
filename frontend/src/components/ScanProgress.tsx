import { Loader2 } from 'lucide-react';
import { AppLogo } from './AppLogo';

interface Props {
  step: string;
  progress: number;
}

export function ScanProgress({ step, progress }: Props) {
  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-3">
        <div className="relative">
          <AppLogo className="w-9 h-9 rounded-lg bg-dark-900/60 ring-1 ring-blue-500/30" />
          <div className="absolute -top-1 -right-1">
            <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
          </div>
        </div>
        <div>
          <div className="font-semibold text-gray-200">Escaneando...</div>
          <div className="text-sm text-gray-400">{step}</div>
        </div>
        <div className="ml-auto text-2xl font-bold text-violet-400">{progress}%</div>
      </div>

      <div className="progress-bar">
        <div
          className="progress-fill"
          style={{ width: `${progress}%` }}
        />
      </div>

      <div className="grid grid-cols-6 gap-1">
        {Array.from({ length: 12 }).map((_, i) => (
          <div
            key={i}
            className={`h-1 rounded-full transition-all duration-300 ${
              (i / 12) * 100 <= progress ? 'bg-violet-500' : 'bg-dark-800'
            }`}
          />
        ))}
      </div>
    </div>
  );
}
