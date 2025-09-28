<template>
  <div class="flex min-h-screen flex-col justify-center px-6 py-12 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-sm">
      <h2 class="mt-10 text-center text-2xl font-bold tracking-tight text-gray-900">
        Reset Your Password
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        Enter a new password to reset your account
      </p>
    </div>

    <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
      <form @submit.prevent="submitReset" class="space-y-6">
        <!-- New Password -->
        <div>
          <label for="password" class="block text-sm font-medium text-gray-900">
            New Password
          </label>
          <input
            v-model="newPassword"
            id="password"
            type="password"
            required
            class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-gray-900 sm:text-sm"
          />
        </div>

        <!-- Confirm Password -->
        <div>
          <label for="confirmPassword" class="block text-sm font-medium text-gray-900">
            Confirm New Password
          </label>
          <input
            v-model="confirmPassword"
            id="confirmPassword"
            type="password"
            required
            class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-gray-900 sm:text-sm"
          />
        </div>

        <!-- Validation Errors -->
        <ul v-if="validationErrors.length" class="text-sm text-red-600 space-y-1">
          <li v-for="(error, index) in validationErrors" :key="index">{{ error }}</li>
        </ul>

        <!-- Submit -->
        <div>
          <button
            type="submit"
            :disabled="loading"
            class="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {{ loading ? "Resetting..." : "Reset Password" }}
          </button>
        </div>
      </form>

      <p v-if="message" class="mt-4 text-center text-sm text-green-600">{{ message }}</p>
      <p class="mt-10 text-center text-sm text-gray-500">
        Back to
        <RouterLink to="/login" class="font-semibold text-indigo-600 hover:text-indigo-500">
          Login
        </RouterLink>
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import { useRoute, useRouter } from "vue-router";
import axios from "../services/axios";

const route = useRoute();
const router = useRouter();

const token = ref("");
const newPassword = ref("");
const confirmPassword = ref("");
const message = ref("");
const loading = ref(false);
const validationErrors = ref([]);

// Extract token from URL query
onMounted(() => {
  token.value = route.query.token || "";
  if (!token.value) {
    message.value = "Invalid or missing reset token.";
  }
});

function validatePasswords() {
  const errors = [];

  if (newPassword.value.length < 8) {
    errors.push("Password must be at least 8 characters long.");
  }
  if (newPassword.value !== confirmPassword.value) {
    errors.push("Passwords do not match.");
  }

  validationErrors.value = errors;
  return errors.length === 0;
}

const submitReset = async () => {
  if (!token.value) return;
  if (!validatePasswords()) return;

  try {
    loading.value = true;
    console.log(token.value)
    console.log(newPassword.value)
    const response = await axios.post("/auth/reset-password", {
      token: token.value,
      newPassword: newPassword.value,
    });
    message.value = response.data;

    // Redirect to login after 2 seconds
    setTimeout(() => router.push("/login"), 2000);
  } catch (error) {
    message.value = error.response?.data || "Failed to reset password.";
  } finally {
    loading.value = false;
  }
};
</script>
