<script setup>
import { ArrowDownTrayIcon, XCircleIcon } from "@heroicons/vue/24/outline";
import { computed } from "vue";

const props = defineProps({
  certificate: {
    type: Object,
    required: true,
  },
  isOwned: {
    type: Boolean,
    default: false,
  },
});

const cardClasses = computed(() =>
  props.certificate.isRevoked
    ? "border-2 border-red-500 shadow-lg bg-white rounded-2xl p-4"
    : "border-2 border-yellow-400 shadow-md bg-white rounded-2xl p-4"
);
</script>

<template>
  <div :class="cardClasses" class="flex flex-col gap-2 w-full max-w-sm font-sans relative p-4">
    <!-- Alias + Type + Keystore -->
    <div class="text-center">
      <h2 class="text-xl md:text-2xl font-serif font-bold text-yellow-700">
        {{ certificate.alias }}
      </h2>
      <p class="text-sm text-gray-600 italic flex justify-center gap-2">
        <span>{{ certificate.certificateType }}</span>
        <span class="font-semibold">| Keystore: {{ certificate.keystoreId }}</span>
      </p>
    </div>

    <!-- Owned / Revoked labels -->
    <div v-if="isOwned" class="absolute top-2 right-2 bg-blue-100 text-blue-800 px-2 py-0.5 rounded-md text-xs">
      Owned
    </div>
    <div v-if="certificate.isRevoked" class="absolute top-2 left-2 bg-red-100 text-red-700 px-2 py-0.5 rounded-md text-xs font-bold">
      REVOKED
    </div>

    <!-- Subject / Role -->
    <div class="text-center mt-3">
      <p class="text-gray-700 font-semibold text-sm md:text-base break-words">
        {{ certificate.subject }}
      </p>
    </div>

    <!-- Serial & Issuer row -->
    <div class="flex justify-between mt-2 text-sm text-gray-700">
      <p><span class="font-semibold">Serial #:</span> {{ certificate.serialNumber }}</p>
      <p><span class="font-semibold">Issuer SN:</span> {{ certificate.issuerSerialNumber || "—" }}</p>
    </div>

    <!-- Actions + Dates -->
    <div class="flex justify-between items-center mt-4 pt-2 border-t border-gray-200">
      <div class="flex gap-2">
        <button class="p-2 bg-green-500 hover:bg-green-600 text-white rounded-md shadow">
          <ArrowDownTrayIcon class="w-5 h-5" />
        </button>

        <button v-if="certificate.canRevoke" class="p-2 bg-red-500 hover:bg-red-600 text-white rounded-md shadow">
          <XCircleIcon class="w-5 h-5" />
        </button>
      </div>

      <div class="text-gray-500 text-xs whitespace-nowrap">
        {{ new Date(certificate.validFrom).toLocaleDateString() }} - {{ new Date(certificate.validTo).toLocaleDateString() }}
      </div>
    </div>
  </div>
</template>
