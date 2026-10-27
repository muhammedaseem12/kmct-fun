import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

if ("serviceWorker" in navigator && import.meta.env.PROD) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/service-worker.js").catch((error) => {
      console.error("Ad service worker registration failed:", error);
    });
  });
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
