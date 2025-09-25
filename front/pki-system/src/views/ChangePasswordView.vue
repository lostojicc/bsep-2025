<script setup>
import { ref } from "vue";
import axios from "../services/axios";
import { useRoute, useRouter } from "vue-router";
import { performLocalLogout } from "../services/authState";

const route = useRoute();
const router = useRouter();

const userId = route.params.userId;

const newPassword = ref("");
const confirmPassword = ref("");

const changePassword = async () => {
  if (newPassword.value !== confirmPassword.value) {
    alert("Passwords do not match!");
    return;
  }

  try {
    await axios.post("/auth/change-password", {
      newPassword: newPassword.value
    });

    alert("Password changed successfully! Please login with your new password.");
    await logout()
  } catch (error) {
    console.error(error);
    alert(`Failed to change password: ${error.response?.data || error.message}`);
  }
};

const logout = async () => {
  try {
    await axios.post("/auth/logout");
  } catch (error) {
    console.error("Logout failed:", error.response?.data || error.message);
  } finally {
    performLocalLogout(router);
  }
};
</script>

<template>
  <div class="flex min-h-screen flex-col justify-center px-6 py-12 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-sm">
      <h2 class="mt-10 text-center text-2xl font-bold tracking-tight text-gray-900">
        Change Temporary Password
      </h2>
    </div>

    <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
      <form @submit.prevent="changePassword" class="space-y-6">
        <div>
          <label for="newPassword" class="block text-sm font-medium text-gray-900">
            New Password
          </label>
          <input v-model="newPassword" type="password" id="newPassword" required
                 class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 sm:text-sm" />
        </div>

        <div>
          <label for="confirmPassword" class="block text-sm font-medium text-gray-900">
            Confirm Password
          </label>
          <input v-model="confirmPassword" type="password" id="confirmPassword" required
                 class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 sm:text-sm" />
        </div>

        <div>
          <button type="submit"
                  class="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-indigo-500">
            Change Password
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
