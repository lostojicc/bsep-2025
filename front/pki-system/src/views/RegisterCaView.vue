<script setup>
import { ref } from "vue";
import axios from "axios";
import { useRouter } from "vue-router";

const router = useRouter();

const name = ref("");
const surname = ref("");
const email = ref("");
const organization = ref("");

const errors = ref({
  name: "",
  surname: "",
  email: "",
  organization: ""
});

const validate = () => {
  let valid = true;

  errors.value = { name: "", surname: "", email: "", organization: "" };

  if (!name.value.trim()) {
    errors.value.name = "First name is required.";
    valid = false;
  }

  if (!surname.value.trim()) {
    errors.value.surname = "Last name is required.";
    valid = false;
  }

  if (!email.value.trim()) {
    errors.value.email = "Email is required.";
    valid = false;
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
    errors.value.email = "Please enter a valid email address.";
    valid = false;
  }

  if (!organization.value.trim()) {
    errors.value.organization = "Organization is required.";
    valid = false;
  }

  return valid;
};

const registerCA = async () => {
  if (!validate()) return;

  const payload = {
    name: name.value,
    surname: surname.value,
    email: email.value,
    organization: organization.value
  };

  try {
    await axios.post("http://localhost:8080/auth/registerCA", payload);

    router.push("/");
  } catch (error) {
    console.error("CA registration failed:", error.response?.data || error.message);
    alert(`CA registration failed: ${error.response?.data?.message || error.message}`);
  }
};
</script>

<template>
  <div class="flex min-h-screen flex-col justify-center px-6 py-12 lg:px-8 bg-gray-50">
    <div class="sm:mx-auto sm:w-full sm:max-w-sm">
      <h2 class="mt-10 text-center text-2xl font-bold tracking-tight text-gray-900">
        Register a CA User
      </h2>
    </div>

    <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
      <form @submit.prevent="registerCA" class="space-y-6">

        <!-- Name -->
        <div>
          <label for="name" class="block text-sm font-medium text-gray-900">First Name</label>
          <input v-model="name" id="name" type="text"
            class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-gray-900 sm:text-sm" />
          <p v-if="errors.name" class="text-red-500 text-sm mt-1">{{ errors.name }}</p>
        </div>

        <!-- Surname -->
        <div>
          <label for="surname" class="block text-sm font-medium text-gray-900">Last Name</label>
          <input v-model="surname" id="surname" type="text"
            class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-gray-900 sm:text-sm" />
          <p v-if="errors.surname" class="text-red-500 text-sm mt-1">{{ errors.surname }}</p>
        </div>

        <!-- Email -->
        <div>
          <label for="email" class="block text-sm font-medium text-gray-900">Email</label>
          <input v-model="email" id="email" type="email"
            class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-gray-900 sm:text-sm" />
          <p v-if="errors.email" class="text-red-500 text-sm mt-1">{{ errors.email }}</p>
        </div>

        <!-- Organization -->
        <div>
          <label for="organization" class="block text-sm font-medium text-gray-900">Organization</label>
          <input v-model="organization" id="organization" type="text"
            class="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-gray-900 sm:text-sm" />
          <p v-if="errors.organization" class="text-red-500 text-sm mt-1">{{ errors.organization }}</p>
        </div>

        <!-- Submit -->
        <div>
          <button type="submit"
            class="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-indigo-500">
            Register CA
          </button>
        </div>

      </form>
    </div>
  </div>
</template>
