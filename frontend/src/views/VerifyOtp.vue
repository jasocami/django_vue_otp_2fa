<script setup>
</script>
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
          <v-otp-input
              v-model="otp"
              length="6"
              type="number"
              :disabled="loading"
              aria-label="Enter 6-digit verification code"
            />
<!--          <v-text-field-->
<!--              class="mt-1" id="otp" prepend-inner-icon="mdi-account" label="OTP"-->
<!--              v-model="otp"-->
<!--              placeholder="OTP" type="text" :rules="otpRules" required color="primary"-->
<!--              variant="underlined">-->
<!--          </v-text-field>-->
          <v-btn class="mt-5 login-button" color="primary" block rounded="lg" size="large"
                 variant="outlined" @click="verify">
            Verify
          </v-btn>
        </v-form>
      </v-col>
    </v-row>
    <v-row>
      <v-col class="mt-5 text-center">
        <v-btn class="mt-5" color="warning" block rounded="lg" size="large" variant="outlined"
          @click="resend">
            Re-send
        </v-btn>
      </v-col>
    </v-row>
    <v-row>
      <v-col>
        ApiError: {{ authStore.apiError }}
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup>
  import { ref, computed } from 'vue';
  import { useAuthStore } from '@/stores';

  const otp = ref('');
  const otpRules = [
    v => !!v || 'OTP is required',
    v => (v && v.length == 6)  || 'OTP must be equal to 6 numbers',
  ];

  const authStore = useAuthStore();

  const verify = async () => {
    const data = { otp_code: otp.value };
    await authStore.verifyOtp(data)
  }

  const resend = async () => {
    await authStore.resendOtp();
  }
</script>

<style>
</style>
