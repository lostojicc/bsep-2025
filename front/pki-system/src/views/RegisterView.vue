<script setup>
import { ref, computed } from "vue";
import axios from "axios";
import zxcvbn from "zxcvbn";
import { useRouter } from "vue-router";

const router = useRouter();

// Form fields
const name = ref("");
const surname = ref("");
const email = ref("");
const organization = ref("");
const password = ref("");
const confirmPassword = ref("");

// Errors
const errors = ref({
  name: "",
  surname: "",
  email: "",
  organization: "",
  password: "",
  confirmPassword: ""
});

// Password visibility
const showPassword = ref(false);
const showConfirmPassword = ref(false);

// Dialog visibility
const showDialog = ref(false);

// Password strength
const passwordScore = computed(() => {
  if (!password.value) return 0;
  return zxcvbn(password.value).score; // 0-4
});

const strengthLabel = computed(() => {
  switch (passwordScore.value) {
    case 0: return { text: "Very Weak", color: "text-red-500", bar: "bg-red-500" };
    case 1: return { text: "Weak", color: "text-orange-500", bar: "bg-orange-500" };
    case 2: return { text: "Fair", color: "text-yellow-500", bar: "bg-yellow-500" };
    case 3: return { text: "Good", color: "text-blue-500", bar: "bg-blue-500" };
    case 4: return { text: "Strong", color: "text-green-500", bar: "bg-green-500" };
    default: return { text: "", color: "text-gray-500", bar: "bg-gray-300" };
  }
});


// Validation function
const validate = () => {
  let valid = true;

  // Reset errors
  errors.value = {
    name: "",
    surname: "",
    email: "",
    organization: "",
    password: "",
    confirmPassword: ""
  };

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

  if (!password.value) {
    errors.value.password = "Password is required.";
    valid = false;
  } else if (password.value.length < 8 || password.value.length > 64) {
    errors.value.password = "Password must be between 8 and 64 characters.";
    valid = false;
  }

  if (!confirmPassword.value) {
    errors.value.confirmPassword = "Please confirm your password.";
    valid = false;
  } else if (password.value !== confirmPassword.value) {
    errors.value.confirmPassword = "Passwords do not match.";
    valid = false;
  }

  return valid;
};

// Submit registration
const register = async () => {
  if (!validate()) return;

  const payload = {
    name: name.value,
    surname: surname.value,
    email: email.value,
    password: password.value,
    organization: organization.value
  };

  try {
    await axios.post("http://localhost:8080/auth/register", payload);
    showDialog.value = true;
  } catch (error) {
    console.error("Registration failed:", error.response?.data || error.message);
    alert(`Registration failed: ${error.response?.data?.message || error.message}`);
  }
};

const closeDialog = () => {
  showDialog.value = false;
  router.push("/login");
};
</script>

<template>
  <div class="flex min-h-screen flex-col justify-center px-6 py-12 lg:px-8 bg-gray-50">
    <div class="sm:mx-auto sm:w-full sm:max-w-sm">
      <img
        src="https://tailwindcss.com/plus-assets/img/logos/mark.svg?color=indigo&shade=600"
        alt="Your Company"
        class="mx-auto h-10 w-auto"
      />
      <h2 class="mt-10 text-center text-2xl font-bold tracking-tight text-gray-900">
        Create your account
      </h2>
    </div>

    <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
      <form @submit.prevent="register" class="space-y-6">
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

        <!-- Password -->
        <div>
          <label for="password" class="block text-sm font-medium text-gray-900">Password</label>
          <div class="mt-2 relative">
            <input
              v-model="password"
              :type="showPassword ? 'text' : 'password'"
              id="password"
              autocomplete="new-password"
              class="block w-full rounded-md border border-gray-300 px-3 py-1.5 pr-10 text-gray-900 sm:text-sm"
            />
            <button type="button" @click="showPassword = !showPassword"
              class="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500">
              <span v-if="showPassword">🙈</span>
              <span v-else>👁️</span>
            </button>
          </div>
          <p v-if="errors.password" class="text-red-500 text-sm mt-1">{{ errors.password }}</p>

          <!-- Password Strength -->
          <div class="mt-2">
            <div class="w-full h-2 bg-gray-200 rounded">
              <div :class="['h-2 rounded', strengthLabel.bar]"
                   :style="{ width: ((passwordScore.value + 1) * 20) + '%' }"></div>
            </div>
            <p class="mt-1 text-sm" :class="strengthLabel.color">{{ strengthLabel.text }}</p>
          </div>
        </div>

        <!-- Confirm Password -->
        <div>
          <label for="confirmPassword" class="block text-sm font-medium text-gray-900">Confirm Password</label>
          <div class="mt-2 relative">
            <input
              v-model="confirmPassword"
              :type="showConfirmPassword ? 'text' : 'password'"
              id="confirmPassword"
              autocomplete="new-password"
              class="block w-full rounded-md border border-gray-300 px-3 py-1.5 pr-10 text-gray-900 sm:text-sm"
            />
            <button type="button" @click="showConfirmPassword = !showConfirmPassword"
              class="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500">
              <span v-if="showConfirmPassword">🙈</span>
              <span v-else>👁️</span>
            </button>
          </div>
          <p v-if="errors.confirmPassword" class="text-red-500 text-sm mt-1">{{ errors.confirmPassword }}</p>
        </div>

        <!-- Submit -->
        <div>
          <button type="submit"
            class="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-indigo-500">
            Register
          </button>
        </div>
      </form>

      <p class="mt-10 text-center text-sm text-gray-500">
        Already have an account?
        <RouterLink to="/login" class="font-semibold text-indigo-600 hover:text-indigo-500">
          Sign in here
        </RouterLink>
      </p>
    </div>

    <!-- Email check dialog -->
    <div v-if="showDialog" class="fixed inset-0 flex items-center justify-center bg-gray-200 bg-opacity-30 z-50">
        <div class="bg-white rounded-lg shadow-lg max-w-sm w-full p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-900">Check Your Email</h3>
            <p class="mt-4 text-gray-700">
            We've sent a confirmation email to <span class="font-medium">{{ email }}</span>. 
            Please check your inbox to activate your account before logging in.
            </p>
            <button
            @click="closeDialog"
            class="mt-6 inline-flex justify-center rounded-md bg-indigo-600 px-4 py-2 text-white font-medium hover:bg-indigo-500"
            >
            OK
            </button>
        </div>
    </div>
  </div>
</template>
