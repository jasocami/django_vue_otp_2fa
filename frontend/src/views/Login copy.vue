<template>
  <v-container>
    <v-row>
      <v-col class="text-center">
        <img alt="Vue logo" class="logo" src="@/assets/logo.svg" width="125" height="125" />
      </v-col>
    </v-row>
    <v-row>
      <v-col class="mt-5">
        <v-form>
          <v-text-field class="mt-1" id="email" prepend-inner-icon="mdi-account" label="E-mail" v-model="email"
          placeholder="Email" type="email" :rules="emailRules" required color="primary" variant="underlined">
          </v-text-field>
          <v-text-field class="mt-1 mb-0" id="password" color="primary"
            :append-inner-icon="visible ? 'mdi-eye-off' : 'mdi-eye'" :type="visible ? 'text' : 'password'"
            prepend-inner-icon="mdi-lock" variant="underlined" label="Password" v-model="password"
            placeholder="Password" required :rules="passwordRules" @click:append-inner="toggleVisibility"
            @keyup.enter="login"></v-text-field>
          <v-btn class="mt-5 login-button" color="primary" block rounded="lg" size="large" variant="outlined"
          @click="login" :disabled="formValid">
            Sign In
          </v-btn>
        </v-form>

      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import { ref, computed } from 'vue';
import { authStore } from '@/stores';
import { getAccessTokenExpiration, getRefreshTokenExpiration, getCookie, setCookie, removeCookies } from '@/utils/cookieManager';

export default {
  setup() {
    const email = ref('');
    const visible = ref(false);
    const password = ref('');
    const emailRules = [
      v => !!v || 'E-email is required',
      v => /.+@.+\..+/.test(v) || 'E-email must be valid',
    ];
    const passwordRules = [
      v => !!v || 'Password is required',
      v => (v && v.length >= 6) || 'Password must be more than 6 characters',
    ];
    const toggleVisibility = () => {
      visible.value = !visible.value;
    };
    const formValid = computed(() => {
      const emailValid = /.+@.+\..+/.test(email.value);
      const passwordValid = password.value && password.value.length >= 6;
      return !(emailValid && passwordValid);
    });

    return {
      emailRules,
      passwordRules,
      email,
      visible,
      password,
      toggleVisibility,
      formValid,
    };
  },
  methods: {
    async login() {
      removeCookies();
      const data = {
        email: email.value,
        password: password.value,
      };
      authStore.login(data).then((response) => {
        console.log(response.data);
        authStore.setUser(response.data.user);
        authStore.setTokens(response.data.tokens);
        router.push('/verify-otp');
      })
      .catch((error) => {
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
      });
    }
  },
}
</script>

<style>
</style>
