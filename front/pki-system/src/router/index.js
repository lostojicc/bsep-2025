import { createRouter, createWebHistory } from "vue-router";
import LoginView from "../views/LoginView.vue";
import HomeView from "../views/HomeView.vue";
import RegisterView from "../views/RegisterView.vue";
import TestView from "../views/TestView.vue";
import SessionsView from "../views/SessionsView.vue";
import ChangePasswordView from "../views/ChangePasswordView.vue";
import RegisterCaView from "../views/RegisterCaView.vue";
import CertificatesView from "../views/CertificatesView.vue";
import AccountRecoveryView from "../views/AccountRecoveryView.vue";
import ResetPasswordView from "../views/ResetPasswordView.vue";
import CSRUploadView from "../views/CSRUploadView.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", name: "home", component: HomeView },
    { path: "/login", name: "login", component: LoginView },
    { path: "/register", name: "register", component: RegisterView },
    { path: "/test", name: "test", component: TestView, meta: { requiresAuth: true, allowedRoles: ["BASIC"] }},
    { path: "/sessions", name: "sessions", component: SessionsView, meta: { requiresAuth: true }},
    { path: "/change-password/:userId", name: "change-password", component: ChangePasswordView, meta: { requiresAuth: true, allowedRoles: ["CA"] } },
    { path: "/register-ca", name: "register-ca", component: RegisterCaView, meta: { requiresAuth: true, allowedRoles: ["ADMIN"] } },
    { path: "/certificates", name: "certificates", component: CertificatesView, meta: { requiresAuth: true } },
    { path: "/recovery", name: "recovery", component: AccountRecoveryView},
    {path: "/reset-password", name: "ResetPassword", component: ResetPasswordView},
    { path: "/csr", name: "CSR", component: CSRUploadView, meta: {requiresAuth: true, allowedRoles: ["BASIC"]}}
  ]
});

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem("authToken");
  const role = localStorage.getItem("userRole");
  const caChangedPassword = localStorage.getItem("caChangedPassword");
  const userId = localStorage.getItem("userId");

  if (to.meta.requiresAuth && !token) {
    return next("/login"); 
  }

  if (role === "CA" && caChangedPassword === 'false' && to.name !== "change-password") {
    return next({ name: "change-password", params: { userId } });
  }

  if (to.meta.allowedRoles && !to.meta.allowedRoles.includes(role)) {
    return next("/"); 
  }

  next();
});

export default router;