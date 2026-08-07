import { useEffect, useRef, useState } from 'react';
import { Camera, QrCode, X } from 'lucide-react';

type BarcodeResult = { rawValue: string };
type NativeBarcodeDetector = {
  detect: (source: HTMLVideoElement) => Promise<BarcodeResult[]>;
};

type BarcodeDetectorConstructor = new (options?: { formats?: string[] }) => NativeBarcodeDetector;

interface Props {
  disabled?: boolean;
  onRead: (value: string) => void;
}

export function QrCodeReaderButton({ disabled, onRead }: Props) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    if (!open) return;

    let cancelled = false;

    async function startCamera() {
      setError('');

      const BarcodeDetector = (window as any).BarcodeDetector as BarcodeDetectorConstructor | undefined;
      if (!BarcodeDetector) {
        setError('Leitor de QR code indisponivel neste navegador.');
        return;
      }

      if (!navigator.mediaDevices?.getUserMedia) {
        setError('Camera indisponivel neste navegador.');
        return;
      }

      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: 'environment' } },
          audio: false,
        });
        if (cancelled) {
          stream.getTracks().forEach(track => track.stop());
          return;
        }

        streamRef.current = stream;
        const video = videoRef.current;
        if (!video) return;

        video.srcObject = stream;
        await video.play();

        const detector = new BarcodeDetector({ formats: ['qr_code'] });
        const scan = async () => {
          if (!videoRef.current || cancelled) return;
          try {
            const results = await detector.detect(videoRef.current);
            const value = results[0]?.rawValue?.trim();
            if (value) {
              onRead(value);
              setOpen(false);
              return;
            }
          } catch {
            setError('Nao foi possivel ler o QR code.');
          }
          frameRef.current = window.requestAnimationFrame(scan);
        };

        frameRef.current = window.requestAnimationFrame(scan);
      } catch {
        setError('Permita o acesso a camera para ler o QR code.');
      }
    }

    startCamera();

    return () => {
      cancelled = true;
      if (frameRef.current) window.cancelAnimationFrame(frameRef.current);
      frameRef.current = null;
      streamRef.current?.getTracks().forEach(track => track.stop());
      streamRef.current = null;
    };
  }, [open, onRead]);

  return (
    <>
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen(true)}
        title="Ler QR code"
        className="btn-secondary touch-row flex items-center justify-center gap-2 whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <QrCode className="w-4 h-4" />
        QR
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-3 sm:p-4">
          <div className="w-full max-w-lg rounded-lg border border-dark-700 bg-dark-850 p-4 shadow-2xl sm:p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 text-lg font-semibold text-white">
                  <Camera className="w-5 h-5 text-cyan-300" />
                  Ler QR code
                </div>
                <p className="text-sm text-gray-500 mt-1">
                  Aponte a camera para o QR code com a URL do site.
                </p>
              </div>
              <button type="button" onClick={() => setOpen(false)} className="btn-secondary p-2">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-4 overflow-hidden rounded-lg border border-dark-800 bg-dark-900 aspect-video">
              <video ref={videoRef} className="w-full h-full object-cover" playsInline muted />
            </div>

            {error && (
              <div className="mt-3 rounded-lg border border-yellow-800/40 bg-yellow-900/10 px-3 py-2 text-sm text-yellow-300">
                {error}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
