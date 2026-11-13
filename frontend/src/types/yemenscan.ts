/**
 * YemenScan Frontend Type Definitions
 * Strict TypeScript interfaces matching backend models and API contracts.
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ReportType = 'executive' | 'technical';

export type ScanStage = 
  | 'pending'
  | 'phase1_discovery'
  | 'phase2_probing'
  | 'phase3_vulnerabilities'
  | 'completed'
  | 'failed'
  | 'stopped';

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanStats {
  subdomains_count: number;
  open_ports_count: number;
  live_urls_count: number;
  api_endpoints_count: number;
  vulnerabilities_count: number;
  vuln_by_severity?: SeveritySummary;
}

export interface ScanStatusData {
  scan_id: string;
  target_domain: string;
  current_stage: ScanStage | string;
  current_tool: string;
  progress_percentage: number;
  is_completed: boolean;
  error_message: string | null;
  created_at: string;
  updated_at: string;
  completed_at?: string | null;
  stats?: ScanStats;
}

export interface ScanStatusResponse {
  status: 'success' | 'error';
  data: ScanStatusData;
}

export interface ScanStartRequest {
  domain: string;
}

export interface ScanStartResponse {
  status: 'success' | 'error';
  scan_id: string;
  target_domain: string;
  message: string;
  phases: string[];
}

export interface ScanStopResponse {
  status: 'success' | 'error';
  scan_id: string;
  message: string;
}

export interface ScanSessionItem {
  scan_id: string;
  target_domain: string;
  created_at: string;
  current_stage: string;
  progress: number;
  is_completed: boolean;
  stats?: ScanStats;
}

export interface ScansListResponse {
  status: 'success' | 'error';
  scans: ScanSessionItem[];
}

export interface DiscoveryResponse {
  status: 'success' | 'error';
  scan_id: string;
  total_subdomains: number;
  subdomains: string[];
  total_open_ports: number;
  open_ports: string[];
}

export interface LiveWebService {
  url: string;
  status_code: number;
  title?: string;
  webserver?: string;
  tech?: string[];
  content_length?: number;
  host?: string;
}

export interface ApiEndpoint {
  url: string;
  path: string;
  status_code: number;
  content_type?: string;
  content_length?: number;
  is_swagger_or_doc?: boolean;
  is_auth_endpoint?: boolean;
  is_actuator?: boolean;
}

export interface EndpointsResponse {
  status: 'success' | 'error';
  scan_id: string;
  total_live_urls: number;
  live_web_services: LiveWebService[];
  total_api_endpoints: number;
  api_endpoints: ApiEndpoint[];
}

export interface VulnerabilityItem {
  id: string;
  title: string;
  severity: SeverityLevel | string;
  source?: string;
  category?: string;
  url: string;
  description?: string;
  remediation?: string;
  evidence?: string;
  cve_id?: string | null;
  cwe_id?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  owasp_category?: string | null;
  discovered_at?: string | null;
  raw_output?: Record<string, any>;
}

export interface VulnerabilitiesResponse {
  status: 'success' | 'error';
  scan_id: string;
  total_vulnerabilities_found: number;
  vulnerabilities: VulnerabilityItem[];
  data?: VulnerabilityItem[];
}

export interface AIReportResponse {
  status: 'success' | 'error';
  scan_id: string;
  report_type: ReportType;
  model_used: string;
  cached: boolean;
  ai_report_markdown: string;
}
