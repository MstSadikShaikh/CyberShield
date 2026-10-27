/**
 * CyberShield API Service
 * Centralizes all HTTP communication between the React frontend and Spring Boot backend.
 */

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.DEV ? 'http://localhost:8080' : '');

/**
 * Helper to execute fetch requests with uniform JSON error handling.
 */
async function request(endpoint, options = {}) {
  // Guard: In production, if VITE_API_BASE_URL is not set, avoid requesting nonexistent relative endpoints or localhost
  if (!API_BASE_URL && !import.meta.env.DEV) {
    const unconfiguredErr = new Error(
      'Public backend API not configured. CyberShield frontend is deployed on Vercel, but the Java Spring Boot backend is hosted locally. Set VITE_API_BASE_URL in Vercel project environment variables to connect to a publicly hosted backend.'
    );
    unconfiguredErr.status = 503;
    throw unconfiguredErr;
  }

  const url = `${API_BASE_URL}${endpoint}`;
  const config = {
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...options.headers,
    },
    ...options,
  };

  try {
    const response = await fetch(url, config);
    const contentType = response.headers.get('content-type');
    const isJson = contentType && contentType.includes('application/json');

    if (!isJson) {
      if (!API_BASE_URL) {
        throw new Error(
          'Backend API not connected. The React frontend is deployed on Vercel, but the Java Spring Boot backend is running locally. Set VITE_API_BASE_URL to your public backend URL.'
        );
      }
      throw new Error(`Unexpected non-JSON response from ${url}: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    if (!response.ok) {
      const errorMessage =
        (data && data.message) ||
        (data && data.error) ||
        `HTTP Error ${response.status}: ${response.statusText}`;
      const err = new Error(errorMessage);
      err.status = response.status;
      err.data = data;
      throw err;
    }

    return data;
  } catch (error) {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      const connErr = new Error(
        `Unable to reach CyberShield backend at ${API_BASE_URL || 'configured API endpoint'}. Ensure the Spring Boot service is running.`
      );
      connErr.status = 0;
      throw connErr;
    }
    throw error;
  }
}

export const apiService = {
  /**
   * Scans a URL using the backend ONNX ML pipeline and MySQL persistence.
   */
  async scanUrl(url) {
    return request('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  },

  /**
   * Retrieves recent scan history from MySQL.
   */
  async getRecentScans(limit = 20) {
    return request(`/api/v1/scans?limit=${limit}`);
  },

  /**
   * Retrieves a specific scan record by ID.
   */
  async getScanById(id) {
    return request(`/api/v1/scans/${id}`);
  },

  /**
   * Fetches backend and model health diagnostic information.
   */
  async getHealth() {
    return request('/api/v1/health');
  },
};
