<script setup>
import { ref, onMounted } from "vue";
import axios from "../services/axios";

const sessions = ref([]);
const userId = ref("");

const fetchSessions = async () => {
  try {
    const response = await axios.get(`/session?userId=${userId.value}`); 

    sessions.value = response.data.map(session => ({
      ...session,
      lastActivity: formatDate(session.lastActivity),
      createdAt: formatDate(session.createdAt),
      expiresAt: formatDate(session.expiresAt)
    }));
  } catch (err) {
    console.error("Failed to fetch sessions", err);
  }
};

const revokeSession = async (jti) => {
  try {
    await axios.post("/session/invalidate", { userId: userId.value, jti });

    sessions.value = sessions.value.filter(s => s.jti !== jti);
  } catch (err) {
    console.error("Failed to revoke session", err);
  }
};

onMounted(() => {
    userId.value = localStorage.getItem("userId") || "";

    if(userId.value === "")
        return;

    fetchSessions()
});

const formatDate = (dateString) => {
  if (!dateString) return "";
  const date = new Date(dateString);
  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = date.getFullYear();
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  return `${day}.${month}.${year} ${hours}:${minutes}`;
};

</script>

<template>
  <div class="max-w-7xl mx-auto px-4 py-6">
    <h2 class="text-2xl font-bold text-gray-900 mb-4">Your Active Sessions:</h2>

    <div class="overflow-x-auto">
      <ul role="list" class="divide-y divide-gray-200">
        <li v-for="session in sessions" 
            :key="session.jti"
            class="flex justify-between gap-x-6 py-4 px-2 rounded shadow mb-2 items-center"
            :class="session.currentSession ? 'bg-indigo-50 border-l-4 border-indigo-600' : 'bg-white'">
        
            <div class="flex flex-col sm:flex-row gap-x-4 flex-auto min-w-0">
                <div class="text-sm sm:w-48">
                <p class="font-semibold text-gray-900">IP:</p>
                <p class="text-gray-500 truncate">{{ session.ipAddress }}</p>
                </div>
                <div class="text-sm sm:w-64">
                <p class="font-semibold text-gray-900">Browser:</p>
                <p class="text-gray-500 truncate">{{ session.userAgent }}</p>
                </div>
                <div class="text-sm sm:w-48">
                <p class="font-semibold text-gray-900">Last Activity:</p>
                <p class="text-gray-500">{{ session.lastActivity }}</p>
                </div>
                <div class="text-sm sm:w-48">
                <p class="font-semibold text-gray-900">Expires At:</p>
                <p class="text-gray-500">{{ session.expiresAt }}</p>
                </div>
                <div class="text-sm sm:w-48">
                <p class="font-semibold text-gray-900">Created At:</p>
                <p class="text-gray-500">{{ session.createdAt }}</p>
                </div>
            </div>

            <div class="flex-shrink-0">
                <button @click="revokeSession(session.jti)"
                        :disabled="session.currentSession"
                        :class="session.currentSession 
                                ? 'bg-gray-400 cursor-not-allowed text-white px-3 py-1.5 rounded-md text-sm font-medium' 
                                : 'bg-red-600 hover:bg-red-500 text-white px-3 py-1.5 rounded-md text-sm font-medium'">
                {{ session.currentSession ? "Current Session" : "Revoke" }}
                </button>
            </div>
        </li>
      </ul>
    </div>
  </div>
</template>

<style scoped>
.overflow-x-auto {
  max-height: 70vh;
  overflow-y: auto;
}
</style>