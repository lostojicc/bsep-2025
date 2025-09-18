<script setup>
import { ref } from "vue";
import axios from "../services/axios";
import { useRouter } from "vue-router";

const router = useRouter();

const email = ref("");
const password = ref("");
const showPassword = ref(false);

const login = async () => {
  try {
    const token = await axios.post("/auth/login", {
      email: email.value,
      password: password.value
    }).then(res => res.data);

    localStorage.setItem("authToken", token);

    alert("Login successful!");

    router.push("/");
  } catch (error) {
    console.error("Login failed:", error.response?.data || error.message);
    alert(`Login failed: ${error.response?.data?.message || error.message}`);
  }
};
</script>

<template>
  <div class="flex min-h-screen flex-col justify-center px-6 py-12 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-sm">
      <h2 class="mt-10 text-center text-2xl font-bold tracking-tight text-gray-900">
        Sign in to your account
      </h2>
    </div>

    <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
      <form @submit.prevent="login" class="space-y-6">
        <!-- Email -->
        <div>
          <label for="email" class="block text-sm font-medium text-gray-900">Email address</label>
          <input v-model="email" id="email" type="email" required autocomplete="email"
                 class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-gray-900 sm:text-sm" />
        </div>

        <!-- Password -->
        <div>
          <label for="password" class="block text-sm font-medium text-gray-900">Password</label>
          <div class="relative mt-2">
            <input v-model="password" :type="showPassword ? 'text' : 'password'" id="password" required
                   class="block w-full rounded-md border border-gray-300 px-3 py-1.5 pr-10 text-gray-900 sm:text-sm" />
            <button type="button" @click="showPassword = !showPassword"
                    class="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500">
              <span v-if="showPassword">🙈</span>
              <span v-else>👁️</span>
            </button>
          </div>
        </div>

        <!-- Submit -->
        <div>
          <button type="submit"
                  class="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-indigo-500">
            Sign in
          </button>
        </div>
      </form>

      <p class="mt-10 text-center text-sm text-gray-500">
        Not a member?
        <RouterLink to="/register" class="font-semibold text-indigo-600 hover:text-indigo-500">
          Register here now!
        </RouterLink>
      </p>
    </div>
  </div>
</template>
