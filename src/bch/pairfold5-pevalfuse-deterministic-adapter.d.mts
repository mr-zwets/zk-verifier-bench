export interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
  checkpoint?: string;
}
export const originalArtifactSha256: string;
export function adaptExistingPositives(input: {
  artifactBytes: Buffer;
  catalogBytes: Buffer;
  expectedCatalogSha256: string;
}): {
  originalArtifactSha256: string;
  staticCatalogSha256: string;
  positiveCases: {label: string; steps: RawStep[]}[];
};
