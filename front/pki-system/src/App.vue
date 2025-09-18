<script setup>
import { ref, onMounted } from "vue";
import { useRouter } from "vue-router";

const router = useRouter();
const isAuthenticated = ref(false);

const checkAuth = () => {
  isAuthenticated.value = !!localStorage.getItem("authToken");
};

onMounted(() => {
  checkAuth();
});

const logout = () => {
  localStorage.removeItem("authToken");
  isAuthenticated.value = false;
  router.push("/login");
};
</script>

<template>
  <div class="flex flex-col min-h-screen">
    <nav class="bg-indigo-600 text-white shadow">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex h-16 items-center justify-between">
          <div class="flex items-center space-x-4">
            <RouterLink to="/" class="text-lg font-semibold hover:text-gray-200">
              MyApp
            </RouterLink>

            <!-- Show Login/Register or Logout -->
            <template v-if="isAuthenticated">
              <button @click="logout" class="hover:text-gray-200">
                Logout
              </button>
            </template>
            <template v-else>
              <RouterLink to="/login" class="hover:text-gray-200">
                Login
              </RouterLink>
              <RouterLink to="/register" class="hover:text-gray-200">
                Register
              </RouterLink>
            </template>
          </div>
        </div>
      </div>
    </nav>

    <main class="flex-1">
      <RouterView />
    </main>
  </div>
</template>
