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
            @keyup.enter="login"/>
          <v-btn class="mt-5 login-button" color="primary" block rounded="lg" size="large" variant="outlined"
          @click="login" :disabled="formValid">
            Sign In
          </v-btn>
        </v-form>
      </v-col>
    </v-row>
    <v-row>
      <v-col class="text-center">
        {{ authStore.apiError }}
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup>
  import { ref, computed } from 'vue';
  import { useAuthStore, useGenericStore } from '@/stores';
  import cookieManager from '@/utils/cookieManager';
  import router from '@/router';

  const email = ref('');
  const visible = ref(false);
  const password = ref('');
  const emailRules = [
    v => !!v || 'E-email is required',
    v => /.+@.+\..+/.test(v) || 'E-email must be valid',
  ];
  const passwordRules = [
    v => !!v || 'Password is required',
    v => (v && v.length >= 1) || 'Password must be more than 6 characters',
  ];
  const toggleVisibility = () => {
    visible.value = !visible.value;
  };
  const formValid = computed(() => {
    const emailValid = /.+@.+\..+/.test(email.value);
    const passwordValid = password.value && password.value.length >= 1;
    return !(emailValid && passwordValid);
  });

  const authStore = useAuthStore();

  const login = async () => {
    cookieManager.deleteAll();
    const data = {
      email: email.value,
      password: password.value,
    };
    authStore.login(data);
    console.log('Done');
      // router.push({ name: 'verify_otp' });
/*
import { useRouter } from "vue-router";
const router = useRouter();
  */
  }
</script>

<style>
</style>
