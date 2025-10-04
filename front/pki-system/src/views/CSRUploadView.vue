<template>
  <div class="max-w-xl mx-auto mt-10 p-6 bg-white rounded-lg shadow-md">
    <h2 class="text-xl font-semibold mb-4">Upload CSR</h2>

    <form @submit.prevent="submitCsr">
      <!-- CSR File -->
      <div class="mb-4">
        <label class="block text-sm font-medium mb-1">CSR File (.pem)</label>
        <input
          type="file"
          accept=".pem"
          @change="onFileChange"
          required
          class="w-full border rounded p-2"
        />
      </div>

      <!-- Select CA -->
      <div class="mb-4">
        <label class="block text-sm font-medium mb-1">Certification Authority</label>
        <select v-model="selectedCaId" class="w-full border rounded p-2" required>
          <option disabled value="">-- Select CA --</option>
         <option v-for="ca in cas" :key="ca.id" :value="ca.id">
            {{ ca.name }} ({{ ca.email }})
         </option>
        </select>
      </div>

      <!-- Validity Days -->
      <div class="mb-4">
        <label class="block text-sm font-medium mb-1">Validity (days)</label>
        <input
          type="number"
          v-model="validityDays"
          class="w-full border rounded p-2"
          required
          min="1"
        />
      </div>

      <!-- Submit -->
      <button
        type="submit"
        :disabled="loading"
        class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
      >
        {{ loading ? "Uploading..." : "Upload CSR" }}
      </button>
    </form>

    <!-- Message -->
    <p v-if="message" class="mt-4 text-sm">{{ message }}</p>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import axios from "axios";

const file = ref(null);
const selectedCaId = ref("");
const validityDays = ref("");
const cas = ref([]);
const message = ref("");
const loading = ref(false);

const onFileChange = (e) => {
  file.value = e.target.files[0];
};

const fetchCas = async () => {
  try {
    const res = await axios.get("/user/cas");
    cas.value = res.data;
  } catch (err) {
    console.error("Failed to load CAs", err);
  }
};

const submitCsr = async () => {
  if (!file.value) {
    message.value = "Please upload a CSR file.";
    return;
  }
  if (!selectedCaId.value) {
    message.value = "Please select a Certification Authority.";
    return;
  }
  if (!validityDays.value || validityDays.value <= 0) {
    message.value = "Please enter a valid number of days for validity.";
    return;
  }

  const formData = new FormData();
  formData.append("file", file.value);
  formData.append("caId", selectedCaId.value);
  formData.append("validityDays", validityDays.value);

  try {
    loading.value = true;
    const res = await axios.post("/csr/api/csr/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    message.value = res.data?.message || "CSR uploaded successfully.";

    file.value = null;
    selectedCaId.value = "";
    validityDays.value = "";
    
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) fileInput.value = null;

  } catch (err) {
    message.value = err.response?.data?.message || "Upload failed.";
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  fetchCas();
});
</script>
