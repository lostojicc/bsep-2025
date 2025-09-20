import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import router from './router'
import { install } from "vue3-recaptcha-v2";

import Vue3Toastify from "vue3-toastify";
import "vue3-toastify/dist/index.css";

const siteKey = import.meta.env.VITE_RECAPTCHA_SITE_KEY;

createApp(App)
    .use(install, {
        sitekey: siteKey})
    .use(router)
    .use(Vue3Toastify, { autoClose: 3000,})
    .mount('#app')