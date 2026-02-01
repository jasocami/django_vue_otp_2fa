import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore, useUsersStore } from '@/stores';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: import('@/views/Login.vue'),
    },
    {
      path: '/verify-otp',
      name: 'verify_otp',
      component: import('@/views/VerifyOtp.vue'),
      beforeEnter: checkPermission,
    },
    {
      path: '/',
      name: 'home',
      component: import('@/views/Home.vue'),
      beforeEnter: checkPermission,
    },
  ],
})

async function checkPermission(to, from, next) {
  // redirect to login page if not logged in and trying to access a restricted page

  // Check that there is a token
  const authStore = useAuthStore();
  const a_token = authStore.getAccessToken;
  console.log('a_token', a_token);
  if (!a_token) {
    return next({ name: 'login' });
  }
  // Check that the user has approved otp code
  const userStore = useUsersStore();
  await userStore.getMe();
  // .then((response) => {
  //   console.log(response.data);
  console.log('userStore.isOtpVerified', authStore.isOtpVerified);
  if (to.name !== 'verify_otp' && !authStore.isOtpVerified) {
    next({ name: 'verify_otp' });
  }
  else if (to.name === 'verify_otp' && authStore.isOtpVerified) {
    next({ name: 'home' });
  }
  // }).catch((error) => {
  //   console.log(error);
  //   return next({ name: from.name });
  // });
  return next();
  // const publicPages = ['/login'];
  // const authRequired = !publicPages.includes(to.path);
  // const auth = useGenericStore();
  // console.log(authRequired, !auth.user);
  // if (authRequired && !auth.user) {
  //   console.log('in');
  //   // auth.returnUrl = to.fullPath;
  //   return '/login';
  // }
}

export default router;
