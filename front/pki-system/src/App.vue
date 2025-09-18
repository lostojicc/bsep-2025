<script setup>
</script>

<template>
  <div class="flex flex-col min-h-screen">
    <nav class="bg-indigo-600 text-white shadow">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex h-16 items-center justify-between">
          <div class="flex items-center space-x-4">
            <RouterLink to="/" class="text-lg font-semibold hover:text-gray-200">
              MyApp
            </RouterLink>
            <RouterLink to="/login" class="hover:text-gray-200">
              Login
            </RouterLink>
            <RouterLink to="/register" class="hover:text-gray-200">
              Register
            </RouterLink>
          </div>
        </div>
      </div>
    </nav>

    <main class="flex-1">
      <RouterView />
    </main>
  </div>
</template>

<style scoped>
</style>
