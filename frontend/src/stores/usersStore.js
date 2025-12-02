import { defineStore } from 'pinia';
import { coreServices } from '@/utils/coreServices'


export const useUsersStore = defineStore({
    id: 'users',
    state: () => ({
        user:  null,
        blocked: null,
    }),
    actions: {
        async getMe() {
            const response = await coreServices().get('/users/me/');
            this.user = response.data;
        },
        async getBlocked() {
            const response = await coreServices().get('/users/blocked/');
            this.blocked = response.data;
        },
    }
});