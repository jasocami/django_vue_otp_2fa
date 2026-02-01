<template>
  <main>
    <v-container>
      <v-row>
        <v-col cols="6">
          <h1>My info</h1>
          <br>
          <pre>
            Me: {{ usersStore }}
          </pre>
        </v-col>
        <v-col cols="6">
          <h1>My info authStore</h1>
          <br>
          <pre>
            Me: {{ authStore }}
          </pre>
        </v-col>
      </v-row>
      <v-row>
        <v-col>
          <h1>My info blocked</h1>
          <br>
          <pre>
            Blocked: {{ usersStore.blocked }}
          </pre>
        </v-col>
      </v-row>
      <v-row>
        <v-col>
          <h1>Logout</h1>
          <br>
          <v-btn class="mt-5" color="primary" block rounded="lg" @click="authStore.logout()">
            Logout
          </v-btn>
        </v-col>
      </v-row>
    </v-container>
  </main>
</template>

<script setup>
  import { ref } from 'vue';
  import { storeToRefs } from 'pinia';
  import { useUsersStore, useAuthStore } from '@/stores';

  const authStore = useAuthStore();
  const usersStore = useUsersStore();
  usersStore.getMe();
  usersStore.getBlocked();

</script>
