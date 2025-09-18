import { createRouter, createWebHistory } from "vue-router";
import LoginView from "../views/LoginView.vue";
import HomeView from "../views/HomeView.vue";
import RegisterView from "../views/RegisterView.vue";
import TestView from "../views/TestView.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", name: "home", component: HomeView },
    { path: "/login", name: "login", component: LoginView },
    { path: "/register", name: "register", component: RegisterView },
    {
      path: "/test",
      name: "test",
      component: TestView,
      meta: { requiresAuth: true, allowedRoles: ["BASIC"] }
    }
  ]
});

// Navigation guard
router.beforeEach((to, from, next) => {
  const token = localStorage.getItem("authToken");
  const role = localStorage.getItem("userRole");

  if (to.meta.requiresAuth && !token) {
    return next("/login"); 
  }

  if (to.meta.allowedRoles && !to.meta.allowedRoles.includes(role)) {
    return next("/"); 
  }

  next();
});

export default router;