<script setup>
import { ref, onMounted } from "vue";
import axios from "../services/axios";

const message = ref("Loading...");

onMounted(async () => {
  try {
    const res = await axios.get("/basic");
    message.value = res.data;
  } catch (error) {
    console.error("Error fetching /basic:", error);
    message.value = error.response?.data || "Unauthorized";
  }
});
</script>

<template>
  <div class="flex items-center justify-center min-h-screen bg-gray-100">
    <div class="bg-white shadow-lg rounded-lg p-8">
      <h1 class="text-2xl font-bold text-indigo-600">Protected Page</h1>
      <p class="mt-4 text-gray-700">
        {{ message }}
      </p>
    </div>
  </div>
</template>