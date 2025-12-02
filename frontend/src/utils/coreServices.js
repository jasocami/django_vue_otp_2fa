import { getCookie } from '@/utils/cookieManager';
import apiClient from '@/utils/axiosConfig';
import { API_BASE_URL, defaultHeaders } from '@/utils/apiConfig';

export function coreServices() {
  return {
    baseUrl() { return `${API_BASE_URL}/api`; },
    createUrl(url) {
      if (url.startsWith('http')) return url;
      return `${this.baseUrl()}${url}`;
    },
    async get(url) {
      return apiClient.get(this.createUrl(url), { headers: this.getRequestHeader() });
    },
    async downloadBlob(url, data) {
      return apiClient.post(this.createUrl(url), data, { headers: this.getRequestHeader(), responseType: 'blob' });
    },
    async post(url, data, headers) {
      if (!headers) headers = this.getRequestHeader();
      return apiClient.post(this.createUrl(url), data, { headers: headers });
    },
    async put(url, data) {
      return apiClient.put(this.createUrl(url), data, { headers: this.getRequestHeader() });
    },
    async patch(url, data) {
      return apiClient.patch(this.createUrl(url), data, { headers: this.getRequestHeader() });
    },
    async delete(url) {
      return apiClient.delete(this.createUrl(url), { headers: this.getRequestHeader() });
    },
    getRequestHeader() {
      const accessToken = getCookie('accessToken');
      return defaultHeaders(accessToken);
    },
    getMultipartRequestHeader() {
      const headers = this.getRequestHeader();
      headers['Content-Type'] = 'multipart/form-data';
      return headers;
    },
  };
}
