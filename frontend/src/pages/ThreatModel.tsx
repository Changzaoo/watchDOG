import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Layers, RefreshCw, ShieldAlert } from 'lucide-react';
import { Scan, ThreatModelData } from '@sentinelscope/shared';
import { api } from '../lib/api';
import { ThreatModelPanel } from '../components/ThreatModelPanel';

export function ThreatModel() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [model, setModel] = useState<ThreatModelData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    load();
  }, [id]);

  async function load() {
    if (!id) return;
    try {
      setLoading(true);
      setError('');
      const [scanData, threatModel] = await Promise.all([api.getScan(id), api.getThreatModel(id)]);
      setScan(scanData.scan);
      setModel(threatModel);
    } catch (e: any) {
      setError(e.message || 'Falha ao carregar threat model');
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return <div className="text-gray-400">Carregando threat model...</div>;
  }

  if (error || !model) {
    return (
      <div className="card text-center py-10">
        <ShieldAlert className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <div className="text-gray-300">{error || 'Threat model não encontrado'}</div>
        <button onClick={() => navigate(-1)} className="btn-secondary mt-4">Voltar</button>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-start gap-3">
          <button onClick={() => navigate(-1)} className="btn-secondary p-2 mt-1">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-orange-400" />
              Threat Model
            </h1>
            <p className="text-sm text-gray-500 mt-1">{scan?.projectName || id}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link to={`/scans/${id}/defense-depth`} className="btn-secondary flex items-center gap-2">
            <Layers className="w-4 h-4" />
            Defense Depth
          </Link>
          <button onClick={load} className="btn-secondary p-2">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <ThreatModelPanel model={model} />
    </div>
  );
}
