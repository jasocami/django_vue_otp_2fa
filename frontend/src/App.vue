<template>
  <v-app>
    <v-main>
      <!-- <div v-if="$store.getters.isLoading" class="loading-overlay">
        <span class="loader"></span>
      </div> -->
      <router-view :key="$route.fullPath"></router-view>
    </v-main>
  </v-app>
</template>

<!--<script>-->
<!--import { getCookie } from '@/utils/cookieManager';-->

<!--export default {-->
<!--  setup() {-->
<!--    const accessToken = () => {-->
<!--      const access = getCookie('accessToken');-->
<!--    }-->
<!--    return {-->
<!--    }-->
<!--  }-->
<!--}-->
<!--</script>-->
