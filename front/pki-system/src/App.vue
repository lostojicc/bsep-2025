<script setup>
import { ref, onMounted } from "vue";
import { useRouter } from "vue-router";
import axios from "./services/axios";

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

const logout = async () => {
  try {
    await axios.post("/auth/logout");
    performLocalLogout();
  } 
  catch (error) {
    console.error("Logout failed:", error.response?.data || error.message);
    performLocalLogout();
  }
};

const performLocalLogout = () => {
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
      <div class="flex items-center space-x-10">
        <RouterLink to="/" class="text-lg font-semibold hover:text-gray-200">
          PKI SYSTEM
        </RouterLink>
        
        <template v-if="isAuthenticated">
          <RouterLink
            v-if="userRole === 'BASIC'"
            to="/test"
            class="hover:text-gray-200"
          >
            Test
          </RouterLink>

          <RouterLink
            to="/sessions"
            class="hover:text-gray-200"
          >
            Active sessions
          </RouterLink>
        </template>
      </div>

      <div class="flex items-center space-x-10">
        <template v-if="isAuthenticated">
          <span class="text-sm text-gray-200">
            <b>{{ userRole }}</b> (ID: {{ userId }})
          </span>
          <button @click="logout" class="hover:text-gray-200 cursor-pointer">
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
