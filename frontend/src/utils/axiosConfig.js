import axios from 'axios';
import { API_BASE_URL } from '@/utils/apiConfig';
import cookieManager from '@/utils/cookieManager';
import router from '@/router';
import { useAuthStore } from '@/stores';

// Axios instance
// const apiClient = axios;
const apiClient = axios.create({
  baseURL: API_BASE_URL,
//   withCredentials: true,
});

function getCSRFToken() {
  const cookieValue = document.cookie.split('; ').find(row => row.startsWith('csrftoken='));
  return cookieValue ? cookieValue.split('=')[1] : null;
}

apiClient.interceptors.request.use(
  (config) => {
    const accessToken = cookieManager.get('accessToken');
    // Add access token if exists
    if (accessToken) {
      config.headers['Authorization'] = `Bearer ${accessToken}`;
    }
    // Add CSRF token if exists
    const csrfToken = getCSRFToken();
    if (csrfToken) {
      config.headers['X-CSRFToken'] = csrfToken;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // if the refresh token expired, try to get a new one
      console.log(error);
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const authStore = useAuthStore();
      const refreshToken = authStore.getRefreshToken;
      const accessToken = authStore.getAccessToken;

      if (refreshToken) {
        try {
          const payload = {
            refresh: refreshToken
          };
          // Try to refresh token
          const response = await authStore.refreshToken(payload, accessToken);
          // Save token
          authStore.setAccessToken(response.data.access);
          // Update original request
          originalRequest.headers['Authorization'] = `Bearer ${response.data.access}`;
          return apiClient(originalRequest);
        } catch (refreshError) {
          // If the refresh fails, redirect to login
          localStorage.clear();
          router.push({ name: 'login' });
          return Promise.reject(refreshError);
        }
      } else {
        // Redirect to login of there is no refresh token
        router.push({ name: 'login' });
        return Promise.reject(error);
      }
    }
    return Promise.reject(error);
  }
);

export default apiClient;