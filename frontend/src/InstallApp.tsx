import { useEffect, useState } from 'react';

type InstallPrompt = Event & { prompt: () => Promise<unknown> };

export function InstallApp() {
  const [installer, setInstaller] = useState<InstallPrompt | null>(null);
  useEffect(() => {
    function available(event: Event) {
      event.preventDefault();
      setInstaller(event as InstallPrompt);
    }
    function done() {
      setInstaller(null);
    }
    window.addEventListener('beforeinstallprompt', available);
    window.addEventListener('appinstalled', done);
    return () => {
      window.removeEventListener('beforeinstallprompt', available);
      window.removeEventListener('appinstalled', done);
    };
  }, []);

  if (!installer) return null;
  return <button type="button" onClick={async () => {
    setInstaller(null);
    try { await installer.prompt(); } catch { /* The browser withdrew the prompt. */ }
  }}>Install NORTH</button>;
}
