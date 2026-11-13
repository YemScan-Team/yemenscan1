/**
 * YemenScan Centralized API Client
 * Communicates with the FastAPI backend endpoints.
 */

import {
  ScanStartResponse,
  ScanStopResponse,
  ScanStatusResponse,
  ScansListResponse,
  DiscoveryResponse,
  EndpointsResponse,
  VulnerabilitiesResponse,
  AIReportResponse,
  ReportType,
} from '../types/yemenscan';

const API_BASE_URL = import.meta.env?.VITE_API_URL || '';

class ApiService {
  private async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options?.headers || {}),
      },
    });

    if (!response.ok) {
      let errorDetail = `HTTP Error ${response.status}: ${response.statusText}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          errorDetail = errorJson.detail;
        }
      } catch {
        // use default error message
      }
      throw new Error(errorDetail);
    }

    return response.json() as Promise<T>;
  }

  /**
   * Start a new security assessment scan.
   */
  async startScan(domain: string): Promise<ScanStartResponse> {
    return this.request<ScanStartResponse>('/api/scan/start', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
  }

  /**
   * Stop an active scan session.
   */
  async stopScan(scanId: string): Promise<ScanStopResponse> {
    return this.request<ScanStopResponse>(`/api/scan/${scanId}/stop`, {
      method: 'POST',
    });
  }

  /**
   * Retrieve real-time execution status and metrics for a scan.
   */
  async getScanStatus(scanId: string): Promise<ScanStatusResponse> {
    return this.request<ScanStatusResponse>(`/api/scan/${scanId}/status`);
  }

  /**
   * Fetch all historical scan sessions from database.
   */
  async getScans(): Promise<ScansListResponse> {
    return this.request<ScansListResponse>('/api/scans');
  }

  /**
   * Fetch Phase 1 results: Subdomains and Open Ports.
   */
  async getDiscovery(scanId: string): Promise<DiscoveryResponse> {
    return this.request<DiscoveryResponse>(`/api/scan/${scanId}/discovery`);
  }

  /**
   * Fetch Phase 2 results: Live Web Services and API Endpoints.
   */
  async getEndpoints(scanId: string): Promise<EndpointsResponse> {
    return this.request<EndpointsResponse>(`/api/scan/${scanId}/endpoints`);
  }

  /**
   * Fetch Phase 3 results: Vulnerability findings with CVE/CWE/CVSS metadata.
   */
  async getVulnerabilities(scanId: string): Promise<VulnerabilitiesResponse> {
    return this.request<VulnerabilitiesResponse>(`/api/scan/${scanId}/vulnerabilities`);
  }

  /**
   * Generate or retrieve cached AI Security Advisory Report.
   */
  async getAIReport(scanId: string, reportType: ReportType = 'executive', refresh = false): Promise<AIReportResponse> {
    const query = new URLSearchParams({
      report_type: reportType,
      refresh: String(refresh),
    });
    return this.request<AIReportResponse>(`/api/scan/${scanId}/ai-report?${query.toString()}`);
  }

  /**
   * Returns URLs for direct downloading / viewing of exported reports.
   */
  getExportUrls(scanId: string, reportType: ReportType = 'executive') {
    return {
      markdown: `${API_BASE_URL}/api/scan/${scanId}/export/markdown?report_type=${reportType}`,
      html: `${API_BASE_URL}/api/scan/${scanId}/export/html?report_type=${reportType}`,
      json: `${API_BASE_URL}/api/scan/${scanId}/export/json?report_type=${reportType}`,
    };
  }
}

export const api = new ApiService();
