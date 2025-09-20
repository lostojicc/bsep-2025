import axios from "axios";
import { performLocalLogout } from "./authState";

axios.defaults.baseURL = "http://localhost:8080";
axios.defaults.headers["Content-Type"] = "application/json";

axios.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("authToken");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// izbacuje korisnika iz sesije kada se vrati 401
// moze biti problem ako server baci ex, bacice uvek 401 ili 403
// zakoment ako je problem
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 || error.response?.status === 403) {
      performLocalLogout();
    }
    return Promise.reject(error);
  }
);

export default axios;