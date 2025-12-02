import axios from 'axios';
import { getAccessTokenExpiration, getCookie, setCookie, removeCookies } from './utils/cookieManager';
import router from './router';

let isRefreshing = false;
let failedQueue = [];

// axios.defaults.withCredentials = true;

const processQueue = (error, token = null) => {
  console.log(`Processing queue. Error: ${error}, Token: ${token}, Queue: ${failedQueue.length}`);
  
  failedQueue.forEach((prom, index) => {
    if (error) {
      console.log(`Rejecting promise in posición ${index} due to an error.`);
      prom.reject(error);
    } else {
      console.log(`Resolving promise in queue in posicition ${index} with token: ${token}`);
      prom.resolve(token);
    }
  });

  failedQueue = [];
};

const logout = () => {
  removeCookies();
  router.push('/');
};

axios.interceptors.response.use(
  response => response,
  error => {
    const originalRequest = error.config;
    // console.log(`Interceptor de respuesta. Error: ${error.response.status}, isRefreshing: ${isRefreshing}`);
  
    if (originalRequest.headers.ignoreRefreshToken) {
      console.log('Ignore refresh token for reset password');
      return Promise.resolve();
    }

    if (error.response.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        console.log('Adding a failedQueue because we are already refreshing the token.');
        return new Promise(function(resolve, reject) {
          failedQueue.push({
            resolve: token => {
              console.log("push failedQueue", token);
              originalRequest.headers['Authorization'] = 'Bearer ' + token;
              resolve(axios(originalRequest));
            },
            reject: err => {
              console.log("rejech failedQueue", err);
              reject(err);
            }
          });
        });
      }

      console.log('Init refreshing token.');
      originalRequest._retry = true;
      isRefreshing = true;

      return new Promise(function(resolve, reject) {
        const refreshToken = getCookie('refreshToken');
        if (!refreshToken) {
          console.log('No refresh token available.');
          reject(new Error('No refresh token available.'));
          logout();
          return;
        }
        axios.post(`${import.meta.env.VITE_APP_BASE_URL}/api/token/refresh/`, { refresh: refreshToken }, { withCredentials: true, headers: { 'Content-Type': 'application/json' } })
          .then(response => {
            if (response.status === 200) {
              console.log("AccessToken refreshed");
              setCookie('accessToken', response.data.access, getAccessTokenExpiration());
              originalRequest.headers['Authorization'] = 'Bearer ' + response.data.access;
              processQueue(null, response.data.access);
              resolve(axios(originalRequest));
            }
          })
          .catch((refreshError) => {
            console.log('Error refreshing token.', refreshError);
            logout();
            processQueue(refreshError, null);
            reject(refreshError);
          })
          .finally(() => {
            isRefreshing = false;
          });
      });
    }
    return Promise.reject(error);
  }
);
