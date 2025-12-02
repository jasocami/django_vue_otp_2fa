import { defineStore } from 'pinia';

export const useGenericStore = defineStore('generic', {
  state: () => ({
    isLoading: false,
    isAppLoaded: false,
  }),
  actions: {
    setLoading(isLoading) {
      this.isLoading = isLoading;
    },
    setAppLoaded() {
      this.isAppLoaded = true;
    },
  },
});