<script setup>
import { ref, onMounted } from "vue";

const isAuthenticated = ref(false);

const checkAuth = () => {
  const token = localStorage.getItem("authToken");
  isAuthenticated.value = !!token;
};

onMounted(() => {
  checkAuth();
});

</script>

<template>
  <div class="flex flex-col items-center justify-center min-h-screen bg-gray-50 px-6">
    <div class="max-w-2xl text-center">
      <h1 class="text-4xl font-bold tracking-tight text-gray-900 sm:text-5xl">
        Welcome to MyApp 🎉
      </h1>
      <p class="mt-6 text-lg text-gray-600">
        This is the home page of your Vue 3 + Tailwind app.  
        Use the navigation bar to sign in, register, or explore more pages.
      </p>
      <div class="mt-8 flex gap-4 justify-center" v-if="!isAuthenticated">
        <RouterLink
          to="/login"
          class="rounded-md bg-indigo-600 px-4 py-2 text-white font-semibold shadow hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-600"
        >
          Login
        </RouterLink>
        <RouterLink
          to="/register"
          class="rounded-md bg-gray-100 px-4 py-2 text-gray-900 font-semibold shadow hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-indigo-600"
        >
          Register
        </RouterLink>
      </div>
    </div>
  </div>
</template>