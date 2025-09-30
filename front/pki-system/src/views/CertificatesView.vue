<script setup>
import { ref, onMounted } from "vue";
import CertificateCard from "../components/CertificateCard.vue";
import { authState } from "../services/authState";
import axios from "../services/axios"

const showRoot = ref(true);
const showIntermediate = ref(true);
const showEE = ref(true);

const rootCerts = ref([]);
const intermediateCerts = ref([]);
const eeCerts = ref([]);

onMounted(()=>{
    if(authState.userRole === 'ADMIN'){
        loadOwner();
    }
    else if(authState.userRole === 'CA'){
        loadSigned();
    }
    else if(authState.userRole === 'BASIC'){
        loadOwner()
    }
})

const loadOwner = async () => {
  try {
    const response = await axios.get("/certificate/owner");
    const certificates = response.data;

    rootCerts.value = certificates.filter(c => c.certificateType === "ROOT");
    eeCerts.value = certificates.filter(c => c.certificateType === "END_ENTITY");
  } catch (error) {
    console.error("Load for owner failed:", error.response?.data || error.message);
  }
};

const loadSigned = async () => {
  try {
    const response = await axios.get("/certificate/signed");
    const certificates = response.data;

    intermediateCerts.value = certificates.filter(c => c.certificateType === "INTERMEDIATE");
    eeCerts.value = certificates.filter(c => c.certificateType === "END_ENTITY");
  } catch (error) {
    console.error("Load for owner failed:", error.response?.data || error.message);
  }
};

const loadKeystore = async (keystoreId) => {
  try {
    const response = await axios.get("/certificate/keystore", {
      params: { keystoreId }
    });
    const certificates = response.data;

    intermediateCerts.value = certificates.filter(c => c.certificateType === "INTERMEDIATE");
    eeCerts.value = certificates.filter(c => c.certificateType === "END_ENTITY");
  } catch (error) {
    console.error("Load for keystore failed:", error.response?.data || error.message);
  }
};

const handleRootClick = (cert) => {
  if(authState.userRole === 'ADMIN') {
    loadKeystore(cert.keystoreId)
  }
};

</script>

<template>
  <div class="p-6 space-y-8">
    <div v-if="authState.userRole === 'ADMIN'">
      <div
        class="flex items-center justify-start mb-5 cursor-pointer ml-10"
        @click="showRoot = !showRoot"
      >
        <h2 class="text-2xl font-semibold text-gray-800">Root Certificates</h2>
        <span class="text-l text-blue-600 hover:text-blue-800 ml-10">
          {{ showRoot ? "Minimize ▲" : "Expand ▼" }}
        </span>
      </div>
      <transition name="fade">
        <div
          v-show="showRoot"
          class="max-h-90 overflow-y-auto bg-white rounded-lg shadow p-4"
        >
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            <CertificateCard
                v-for="cert in rootCerts"
                :key="cert.id"
                :certificate="cert"
                :is-owned="cert.ownerId == authState.userId"
                @click="() => handleRootClick(cert)"
                class="cursor-pointer hover:shadow-lg hover:scale-105 transition-all duration-200"
                />
          </div>
        </div>
      </transition>
    </div>

    <div v-if="authState.userRole === 'ADMIN' || authState.userRole ==='CA'">
      <div
        class="flex items-center justify-start mb-5 cursor-pointer ml-10"
        @click="showIntermediate = !showIntermediate"
      >
        <h2 class="text-2xl font-semibold text-gray-800">Intermediate Certificates</h2>
        <span class="text-l text-blue-600 hover:text-blue-800 ml-10">
          {{ showIntermediate ? "Minimize ▲" : "Expand ▼" }}
        </span>
      </div>
      <transition name="fade">
        <div
          v-show="showIntermediate"
          class="max-h-90 overflow-y-auto bg-white rounded-lg shadow p-4"
        >
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            <CertificateCard
              v-for="cert in intermediateCerts"
              :key="cert.id"
              :certificate="cert"
              :is-owned="cert.ownerId == authState.userId"
            />
          </div>
        </div>
      </transition>
    </div>

    <div>
      <div
        class="flex items-center justify-start mb-5 ml-10 cursor-pointer"
        @click="showEE = !showEE"
      >
        <h2 class="text-2xl font-semibold text-gray-800">End Entity Certificates</h2>
        <span class="text-l text-blue-600 hover:text-blue-800 ml-10">
          {{ showEE ? "Minimize ▲" : "Expand ▼" }}
        </span>
      </div>
      <transition name="fade">
        <div
          v-show="showEE"
          class="max-h-90 overflow-y-auto bg-white rounded-lg shadow p-4"
        >
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            <CertificateCard
              v-for="cert in eeCerts"
              :key="cert.id"
              :certificate="cert"
              :is-owned="cert.ownerId == authState.userId"
            />
          </div>
        </div>
      </transition>
    </div>
  </div>
</template>


<style>
.fade-enter-active,
.fade-leave-active {
  transition: all 0.3s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}
</style>
