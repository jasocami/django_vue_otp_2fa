import { defineStore } from 'pinia'
import { coreServices } from '@/utils/coreServices'
import axios from 'axios';
import router from '@/router';
import { getAccessTokenExpiration, getRefreshTokenExpiration, getCookie, setCookie, removeCookies } from '@/utils/cookieManager';


export const useAuthStore = defineStore('auth', {
  state: () => ({
    apiError: null,
    user: null, // getCookie('user'),
    accessToken: getCookie('accessToken'),
    refreshToken: getCookie('refreshToken'),
    isLoading: false,
    isAppLoaded: false,
    resendOtp: null,
  }),
  getters: {
    getAccessToken: (state) => state.accessToken,
    getRefreshToken: (state) => state.refreshToken,
  },
  actions: {
    resetState() {
      this.user = null;
      this.accessToken = null;
      this.refreshToken = null;
      this.isAppLoaded = false;
      removeCookies();
    },
    resetApiError() {
      this.apiError = null;
    },
    setTokens(tokens) {
      setCookie('accessToken', tokens['access'], getAccessTokenExpiration());
      this.accessToken = tokens['access'];
      setCookie('refreshToken', tokens['refresh'], getRefreshTokenExpiration());
      this.refreshToken = tokens['refresh'];
    },
    setAccessToken(token) {
      setCookie('accessToken', token, getAccessTokenExpiration());
      this.accessToken = token;
    },
    async login(data) {
      try {
        const response = await coreServices().post('/users/login/', data, '');
        this.setTokens(response.data['tokens']);
        this.user = response.data['user'];
        router.push({name: 'verify_otp'});
      } catch (error) {
        this.apiError = error.response.data;
        console.log(error);
        if (error.response && error.response.status === 400) {
          const errorCode = error.response.data.code;
          if (errorCode === 'password_expired') {
            console.error('Your password has expired. Check your email in order to update it.');
          } else {
            console.error('Invalid login credentials. Please try again.');
          }
        } else {
          console.error('An error occurred. Please try again.');
        }
      }
    },
    async logout(data) {
      try {
        await coreServices().post('/users/logout/', data, '');
        router.push({name: 'login'});
      } catch (error) {
        console.log(error);
        this.apiError = error.response.data;
      }
    },
    async verifyOtp(data) {
      try {
        await coreServices().post('/users/verify-otp/', data);
        router.push({ name: 'home' });
      } catch (error) {
        console.log(error);
        this.apiError = error.response.data;
      }
    },
    async resendOtp() {
      try {
        await coreServices().post('/users/resend-otp/', {}, '');
      } catch (error) {
        console.log(error);
        this.apiError = error.response.data;
      }
    },
    async refreshToken(data, authorization) {
      return coreServices().post('/users/token/refresh/', data, defaultHeaders(authorization));
    },
    validateToken(token) {
      // TODO: change to coreServices
      axios.get('/api/users/me/', {
        headers: { 'Authorization': `Bearer ${token}` }
      }).then(response => {
        commit('setUser', response.data);
        commit('setAppLoaded');
      }).catch(error => {
        console.error("Token validation failed", error);
        this.$router.push('/login');
      });
    },
  },
});
