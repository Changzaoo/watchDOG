import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { ScanSummary } from '@sentinelscope/shared';

interface Props {
  summary: ScanSummary;
}

const SEVERITIES = [
  { key: 'critical', label: 'Crítica', color: '#ef4444' },
  { key: 'high', label: 'Alta', color: '#f97316' },
  { key: 'medium', label: 'Média', color: '#eab308' },
  { key: 'low', label: 'Baixa', color: '#3b82f6' },
  { key: 'info', label: 'Info', color: '#6b7280' },
];

export function SeverityChart({ summary }: Props) {
  const data = SEVERITIES
    .map(s => ({ ...s, value: summary[s.key as keyof ScanSummary] as number }))
    .filter(s => s.value > 0);

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-40 text-gray-600 text-sm">
        Nenhum achado encontrado
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={80}
          paddingAngle={3}
          dataKey="value"
        >
          {data.map((entry, index) => (
            <Cell key={index} fill={entry.color} stroke="transparent" />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ backgroundColor: '#16213e', border: '1px solid #2a2a4a', borderRadius: '8px' }}
          labelStyle={{ color: '#e2e8f0' }}
          formatter={(value: any, name: any) => [value, name]}
        />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }}
          formatter={(value) => SEVERITIES.find(s => s.key === value)?.label || value}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
