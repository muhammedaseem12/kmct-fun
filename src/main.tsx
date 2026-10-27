import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

async function removeAdServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  try {
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(
      registrations
        .filter((registration) => {
          const urls = [
            registration.active?.scriptURL,
            registration.waiting?.scriptURL,
            registration.installing?.scriptURL,
          ].filter(Boolean) as string[];
          return urls.some((url) => {
            try {
              const parsed = new URL(url);
              return parsed.hostname === window.location.hostname &&
                (parsed.pathname === "/service-worker.js" || parsed.pathname.includes("sw.js"));
            } catch {
              return false;
            }
          });
        })
        .map((registration) => registration.unregister())
    );
  } catch (error) {
    console.error("Could not unregister old ad service worker:", error);
  }
}

void removeAdServiceWorker();

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
