<script setup>
import { ref, onMounted } from "vue";
import { useRouter } from "vue-router";
import axios from "./services/axios";
import { authState, performLocalLogout, setRouter } from "./services/authState";
import { toast } from "vue3-toastify";

const router = useRouter();

const logout = async () => {
  try {
    await axios.post("/auth/logout");
  } catch (error) {
    console.error("Logout failed:", error.response?.data || error.message);
  } finally {
    performLocalLogout(router);
  }
};

onMounted(()=>{
  setRouter(router)
})

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

            <template v-if="authState.isAuthenticated">
              <RouterLink
                v-if="authState.userRole === 'BASIC'"
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

              <RouterLink
                v-if="authState.userRole === 'ADMIN'"
                to="/register-ca"
                class="hover:text-gray-200"
              >
                Add new CA
              </RouterLink>

              <RouterLink
                to="/certificates"
                class="hover:text-gray-200"
              >
                Certificates
              </RouterLink>
              <RouterLink
              v-if="authState.userRole === 'BASIC'"
                to="/csr"
                class="hover:text-gray-200"
              >
                CSR upload
              </RouterLink>
            </template>
          </div>

          <div class="flex items-center space-x-10">
            <template v-if="authState.isAuthenticated">
              <span class="text-sm text-gray-200">
                <b>{{ authState.userRole }}</b> (ID: {{ authState.userId }})
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
