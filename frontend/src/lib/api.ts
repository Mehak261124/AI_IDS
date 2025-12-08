/**
 * API service for connecting to the AI_IDS backend
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export interface ApiHealthResponse {
  status: string;
  timestamp?: number;
  models?: {
    binary: string;
    multiclass: string;
    anomaly: string;
  };
}

export interface FlowData {
  Label: string;
  Attack_Type?: string;
  [key: string]: any; // Allow other flow properties
}

export interface ApiPredictResponse {
  status: string;
  file_type: string;
  filename: string;
  file_size_bytes: number;
  total_flows: number;
  summary: {
    BENIGN?: number;
    ATTACK?: number;
    ANOMALY?: number;
  };
  attack_types?: Record<string, number>;
  download_csv: string;
  data_preview: FlowData[];
  all_flows: FlowData[];
}

/**
 * Check API health
 */
export async function checkApiHealth(): Promise<ApiHealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error('API server is not responding');
  }
  return response.json();
}

/**
 * Upload a file and get predictions
 */
export async function predictFile(file: File): Promise<ApiPredictResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/predict`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
    throw new Error(error.detail || `HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Download a CSV file
 */
export function getDownloadUrl(filename: string): string {
  return `${API_BASE_URL}/download/${filename}`;
}

/**
 * Download a CSV file as a blob
 */
export async function downloadCsv(filename: string): Promise<Blob> {
  const response = await fetch(getDownloadUrl(filename));
  if (!response.ok) {
    throw new Error('Failed to download CSV file');
  }
  return response.blob();
}

/**
 * Live Monitoring API Types
 */
export interface LiveStatusResponse {
  running: boolean;
  last_capture: string | null;
  flows: number;
  summary: {
    BENIGN: number;
    ANOMALY: number;
    ATTACK: number;
  };
  attack_types?: Record<string, number>;
  all_flows?: FlowData[];
}

/**
 * Start live network monitoring
 */
export async function startLiveMonitoring(): Promise<{ status: string }> {
  const response = await fetch(`${API_BASE_URL}/start_live`, {
    method: 'POST',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to start live monitoring' }));
    throw new Error(error.detail || `HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Stop live network monitoring
 */
export async function stopLiveMonitoring(): Promise<{ status: string }> {
  const response = await fetch(`${API_BASE_URL}/stop_live`, {
    method: 'POST',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to stop live monitoring' }));
    throw new Error(error.detail || `HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Get current live monitoring status
 */
export async function getLiveStatus(): Promise<LiveStatusResponse> {
  const response = await fetch(`${API_BASE_URL}/live_status`);

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}
