<script setup>
import { ref, onMounted } from "vue";
import { useRouter } from "vue-router";

const router = useRouter();
const isAuthenticated = ref(false);
const userRole = ref("");
const userId = ref("");

const checkAuth = () => {
  const token = localStorage.getItem("authToken");
  isAuthenticated.value = !!token;

  if (isAuthenticated.value) {
    userRole.value = localStorage.getItem("userRole") || "";
    userId.value = localStorage.getItem("userId") || "";
  } else {
    userRole.value = "";
    userId.value = "";
  }
};

onMounted(() => {
  checkAuth();
});

const logout = () => {
  localStorage.removeItem("authToken");
  localStorage.removeItem("userRole");
  localStorage.removeItem("userId");
  isAuthenticated.value = false;
  userRole.value = "";
  userId.value = "";
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

            <!-- Show different links depending on auth state -->
            <template v-if="isAuthenticated">
              <span class="text-sm text-gray-200">
                <b>{{ userRole }}</b> (ID: {{ userId }})
              </span>
              <RouterLink
                v-if="userRole === 'BASIC'"
                to="/test"
                class="hover:text-gray-200"
              >
                Test
              </RouterLink>
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
