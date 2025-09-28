<script setup>
import { ref } from "vue";
import axios from "../services/axios";

const email = ref("");
const loading = ref(false);

const recoverAccount = async () => {
  try {
    loading.value = true;
    await axios.post("/auth/recovery", {
      email: email.value,
    });
    alert("If this email exists, a recovery link has been sent.");
  } catch (error) {
    console.error("Recovery failed:", error.response?.data || error.message);
    alert(`Recovery failed: ${error.response?.data?.message || error.message}`);
  } finally {
    loading.value = false;
  }
};
</script>

<template>
  <div class="flex min-h-screen flex-col justify-center px-6 py-12 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-sm">
      <h2 class="mt-10 text-center text-2xl font-bold tracking-tight text-gray-900">
        Account Recovery
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        Enter your email to receive a password reset link
      </p>
    </div>

    <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
      <form @submit.prevent="recoverAccount" class="space-y-6">
        <!-- Email -->
        <div>
          <label for="email" class="block text-sm font-medium text-gray-900">Email address</label>
          <input
            v-model="email"
            id="email"
            type="email"
            required
            autocomplete="email"
            class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-gray-900 sm:text-sm"
          />
        </div>

        <!-- Submit -->
        <div>
          <button
            type="submit"
            :disabled="loading"
            class="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {{ loading ? "Sending..." : "Send Recovery Link" }}
          </button>
        </div>
      </form>
      <p v-if="message" class="mt-4 text-center text-sm text-green-600">{{ message }}</p>
      <p class="mt-10 text-center text-sm text-gray-500">
        Remember your password?
        <RouterLink to="/login" class="font-semibold text-indigo-600 hover:text-indigo-500">
          Back to Sign in
        </RouterLink>
      </p>
    </div>
  </div>
</template>
