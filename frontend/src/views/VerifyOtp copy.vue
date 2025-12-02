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
          <v-text-field class="mt-1" id="otp" prepend-inner-icon="mdi-account" label="OTP" v-model="otp"
          placeholder="OTP" type="text" :rules="otpRules" required color="primary" variant="underlined">
          </v-text-field>
          <v-btn class="mt-5 login-button" color="primary" block rounded="lg" size="large" variant="outlined"
          @click="verify">
            Verify
          </v-btn>
        </v-form>

      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import { ref, computed } from 'vue';
import { authStore } from '@/stores/authStore';
import { getAccessTokenExpiration, getRefreshTokenExpiration, getCookie, setCookie, removeCookies } from '@/utils/cookieManager';

export default {
  setup() {
    const otp = ref('');
    const otpRules = [
      v => !!v || 'OTP is required',
      v => (v && v.length == 6)  || 'OTP must be equal to 6 numbers',
    ];
    // const formValid = computed(() => {
    //   const emailValid = /.+@.+\..+/.test(email.value);
    //   const passwordValid = password.value && password.value.length >= 6;
    //   return !(emailValid && passwordValid);
    // });

    return {
      otpRules,
      otp,
      // formValid,
    };
  },
  methods: {
    async verify() {
      removeCookies();
      const data = { otp_code: otp.value };
      authStore.verifyOtp(data).then((response) => {
        console.log(response.data);
        router.push('/');
      })
      .catch((error) => {
        console.log(error);
      });
    }
  },
}
</script>

<style>
</style>
