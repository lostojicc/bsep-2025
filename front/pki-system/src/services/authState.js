import { reactive } from "vue";

export const authState = reactive({
  isAuthenticated: !!localStorage.getItem("authToken"),
  userRole: localStorage.getItem("userRole") || "",
  userId: localStorage.getItem("userId") || "",
   router: null 
});

export const setRouter = (router) => {
  authState.router = router;
};

export const performLocalLogout = () => {
  localStorage.removeItem("authToken");
  localStorage.removeItem("userRole");
  localStorage.removeItem("userId");
  localStorage.removeItem("userEmail");
  localStorage.removeItem("caChangedPassword");

  authState.isAuthenticated = false;
  authState.userRole = "";
  authState.userId = "";

  authState.router.push("/login");
};