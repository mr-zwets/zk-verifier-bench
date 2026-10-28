export interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
  checkpoint?: string;
}
export interface Profile {
  id: string;
  originalId: string;
  verificationKeyScope: string;
  file: string;
  originalSha256: string;
  declaredVm: 'bch-2026' | 'bch-spec';
  guardInput: number;
  n0Push: number;
  n1Push: number;
  guardPlacement?: 'locking';
  programs: string[];
  lockings: string[];
  originalPrograms: string[];
  originalLockings: string[];
}
export function adaptExistingPositives(artifactBytes: Buffer, profile: Profile): {name: string; steps: RawStep[]}[];
