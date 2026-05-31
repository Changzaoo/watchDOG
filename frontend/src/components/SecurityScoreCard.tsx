import { scoreColor, scoreLabel, scoreClass } from '../lib/utils';

interface Props {
  score: number;
  size?: 'sm' | 'lg';
}

export function SecurityScoreCard({ score, size = 'lg' }: Props) {
  const color = scoreColor(score);
  const label = scoreLabel(score);
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (score / 100) * circumference;

  if (size === 'sm') {
    return (
      <div className="flex items-center gap-2">
        <span className={`text-2xl font-bold ${scoreClass(score)}`}>{score}</span>
        <div>
          <div className="text-xs text-gray-500">Score</div>
          <div className="text-xs font-medium" style={{ color }}>{label}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-32 h-32">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="45" fill="none" stroke="#1a1a2e" strokeWidth="8" />
          <circle
            cx="50" cy="50" r="45"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 1s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold" style={{ color }}>{score}</span>
          <span className="text-xs text-gray-500">/100</span>
        </div>
      </div>
      <div className="text-center">
        <div className="text-sm font-semibold" style={{ color }}>{label}</div>
        <div className="text-xs text-gray-500 mt-0.5">Pontuação de Segurança</div>
      </div>
    </div>
  );
}
