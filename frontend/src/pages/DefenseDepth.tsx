import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { DefenseLayerData, Scan } from '@sentinelscope/shared';
import { api } from '../lib/api';
import { DefenseDepthPanel } from '../components/DefenseDepthPanel';

export function DefenseDepth() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [layers, setLayers] = useState<DefenseLayerData[]>([]);
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
      const [scanData, defenseLayers] = await Promise.all([api.getScan(id), api.getDefenseDepth(id)]);
      setScan(scanData.scan);
      setLayers(defenseLayers);
    } catch (e: any) {
      setError(e.message || 'Falha ao carregar defense depth');
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return <div className="text-gray-400">Carregando defense depth...</div>;
  }

  if (error) {
    return (
      <div className="card text-center py-10">
        <ShieldAlert className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <div className="text-gray-300">{error}</div>
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
              <ShieldCheck className="w-5 h-5 text-green-400" />
              Defense Depth
            </h1>
            <p className="text-sm text-gray-500 mt-1">{scan?.projectName || id}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link to={`/scans/${id}/threat-model`} className="btn-secondary flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" />
            Threat Model
          </Link>
          <button onClick={load} className="btn-secondary p-2">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <DefenseDepthPanel layers={layers} />
    </div>
  );
}
