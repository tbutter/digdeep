import { useCallback, useEffect, useState } from 'react';

interface BeforeInstallPromptEvent extends Event {
  readonly platforms: string[];
  readonly userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
  prompt(): Promise<void>;
}

export function registerPwaServiceWorker(): void {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
  if (import.meta.env.DEV) return; // Avoid SW caching interfering with Vite HMR in dev mode

  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('./sw.js', { scope: './' })
      .then((reg) => {
        const warmCurrentAssets = (worker: ServiceWorker | null) => {
          if (!worker) return;
          const urls = Array.from(
            document.querySelectorAll<HTMLScriptElement | HTMLLinkElement>(
              'script[src], link[rel="stylesheet"][href]'
            )
          )
            .map((el) => ('src' in el ? el.src : el.href))
            .filter((u) => u.startsWith(window.location.origin));
          if (urls.length > 0) {
            worker.postMessage({ type: 'CACHE_URLS', urls });
          }
        };

        if (reg.active) {
          warmCurrentAssets(reg.active);
        }
        reg.addEventListener('updatefound', () => {
          const installing = reg.installing;
          if (!installing) return;
          installing.addEventListener('statechange', () => {
            if (installing.state === 'activated') {
              warmCurrentAssets(installing);
            }
          });
        });
      })
      .catch(() => {
        // Ignore SW registration failure on unsupported/insecure contexts
      });
  });
}

export function usePwaInstall() {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isStandalone, setIsStandalone] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return (
      window.matchMedia?.('(display-mode: standalone)').matches === true ||
      (navigator as unknown as { standalone?: boolean }).standalone === true
    );
  });
  const [isOffline, setIsOffline] = useState<boolean>(() =>
    typeof navigator !== 'undefined' ? !navigator.onLine : false
  );

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const onBeforeInstall = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
    };

    const onInstalled = () => {
      setDeferredPrompt(null);
      setIsStandalone(true);
    };

    const onOnline = () => setIsOffline(false);
    const onOffline = () => setIsOffline(true);

    window.addEventListener('beforeinstallprompt', onBeforeInstall);
    window.addEventListener('appinstalled', onInstalled);
    window.addEventListener('online', onOnline);
    window.addEventListener('offline', onOffline);

    return () => {
      window.removeEventListener('beforeinstallprompt', onBeforeInstall);
      window.removeEventListener('appinstalled', onInstalled);
      window.removeEventListener('online', onOnline);
      window.removeEventListener('offline', onOffline);
    };
  }, []);

  const promptInstall = useCallback(async () => {
    if (!deferredPrompt) return;
    await deferredPrompt.prompt();
    const choice = await deferredPrompt.userChoice;
    if (choice.outcome === 'accepted') {
      setDeferredPrompt(null);
    }
  }, [deferredPrompt]);

  return {
    canInstall: Boolean(deferredPrompt) && !isStandalone,
    isStandalone,
    isOffline,
    promptInstall,
  };
}
