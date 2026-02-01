import { defineStore } from 'pinia'
import { coreServices } from '@/utils/coreServices'
import axios from 'axios';
import router from '@/router';
import cookieManager from '@/utils/cookieManager';


export const useAuthStore = defineStore('auth', {
  state: () => ({
    apiError: null,
    user: null, // getCookie('user'),
    accessToken: cookieManager.get('accessToken'),
    refreshToken: cookieManager.get('refreshToken'),
    otpVerified: cookieManager.hasOtpVerified(),
    isLoading: false,
    isAppLoaded: false,
    resendOtp: null,
  }),
  getters: {
    getAccessToken: (state) => state.accessToken,
    getRefreshToken: (state) => state.refreshToken,
    isOtpVerified: (state) => state.otpVerified,
  },
  actions: {
    resetState() {
      this.user = null;
      this.accessToken = null;
      this.refreshToken = null;
      this.otpVerified = false;
      this.isAppLoaded = false;
      cookieManager.deleteAll();
    },
    resetApiError() {
      this.apiError = null;
    },
    setTokens(tokens) {
      cookieManager.set('accessToken', tokens['access']);
      this.accessToken = tokens['access'];
      cookieManager.set('refreshToken', tokens['refresh']);
      this.refreshToken = tokens['refresh'];
    },
    async login(data) {
      try {
        const response = await coreServices().post('/users/login/', data, '');
        this.setTokens(response.data['tokens']);
        this.user = response.data['user'];
        console.log('response.data.user.otp_verified', response.data.user.otp_verified)
        cookieManager.setOtpVerified(response.data.user.otp_verified);
        if (response.data.user.otp_verified === false) {
          router.push({ name: 'verify_otp' });
        } else {
          router.push({ name: 'Home' });
        }
      } catch (error) {
        this.apiError = error.response.data;

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
        cookieManager.setOtpVerified(true);
        this.otpVerified = true
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
