import { create } from "zustand";
import type { AnalyzeInput, ScenarioResult } from "./types";

export const GPU_SKUS = [
  "RTX 6000 Ada",
  "RTX PRO 6000 Blackwell Workstation Edition",
  "H100 SXM 80 GB",
  "H200 SXM 141 GB",
  "B200 SXM 180 GB",
] as const;

interface UiState {
  inputs: AnalyzeInput;
  result: ScenarioResult | null;
  loading: boolean;
  error: string | null;
  setInputs: (partial: Partial<AnalyzeInput>) => void;
  setResult: (r: ScenarioResult | null) => void;
  setLoading: (v: boolean) => void;
  setError: (e: string | null) => void;
}

const DEFAULT_INPUT: AnalyzeInput = {
  configJson: "",
  gpu: "B200 SXM 180 GB",
  count: 1,
  tensorParallel: 1,
  replicas: null,
  weightPrecision: "nvfp4",
  kvPrecision: "fp8",
  avgContextTokens: 32768,
  maxContextTokens: 1048576,
  avgOutputTokens: 512,
  sloTargetSeconds: 10.0,
  isHypotheticalWeight: true,
};

export const useStore = create<UiState>()((set) => ({
  inputs: DEFAULT_INPUT,
  result: null,
  loading: false,
  error: null,
  setInputs: (partial) => set((s) => ({ inputs: { ...s.inputs, ...partial } })),
  setResult: (result) => set({ result, error: null, loading: false }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error, result: null, loading: false }),
}));
