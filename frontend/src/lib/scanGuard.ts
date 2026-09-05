/**
 * Decide se a tela de resultado deve mandar o usuário de volta ao formulário de
 * scan de URL — o caso de um scan LOCAL aberto num backend que não permite scan
 * local (produção/Vercel).
 *
 * ⚠️ Isto virou função própria porque a versão inline tinha um bug que custava
 * um scan inteiro ao usuário: a condição era
 *
 *     backendHealthChecked && currentScan?.type !== 'url' && !localScansEnabled
 *
 * e `currentScan` é global na store, começando `null`. No PRIMEIRO scan da
 * sessão o efeito rodava antes de o loadScan() preencher a store, então
 * `undefined !== 'url'` dava true e o redirect disparava — a análise recém
 * criada sumia da tela. Na segunda tentativa a store já tinha um scan 'url' do
 * ciclo anterior e o guard passava: era o "só funciona na segunda vez".
 *
 * A regra correta exige evidência POSITIVA de que o scan é local: carregado,
 * do id da rota atual, e com type diferente de 'url'.
 */
export interface ScanGuardInput {
  /** Ainda buscando o scan no backend? Enquanto true não há o que decidir. */
  loading: boolean;
  /** O /health já respondeu? Antes disso `localScansEnabled` não é confiável. */
  backendHealthChecked: boolean;
  /** Este backend aceita scan local? */
  localScansEnabled: boolean;
  /** Id da rota atual. */
  routeId: string | undefined;
  /** Scan carregado na store (global — pode ser de outra tela). */
  scan: { id: string; type: string } | null | undefined;
}

export function shouldRedirectToUrlScan(input: ScanGuardInput): boolean {
  const { loading, backendHealthChecked, localScansEnabled, routeId, scan } = input;

  if (loading) return false;                 // ainda carregando: não decide
  if (!backendHealthChecked) return false;   // não sabemos se local é permitido
  if (localScansEnabled) return false;       // backend aceita local: nada a fazer
  if (!scan) return false;                   // sem scan carregado: não presume
  if (scan.id !== routeId) return false;     // scan de outra tela: ignora
  return scan.type !== 'url';                // só então: é local e não pode
}
