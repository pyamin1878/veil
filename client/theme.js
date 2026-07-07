// Theme handling. Loaded as a blocking classic script in <head> so the stored
// choice applies before first paint (the CSP forbids inline scripts).
// No stored choice = follow the system preference.
(() => {
  const KEY = 'veil-theme';

  const stored = localStorage.getItem(KEY);
  if (stored === 'dark' || stored === 'light') {
    document.documentElement.dataset.theme = stored;
  }

  function effectiveTheme() {
    return (
      document.documentElement.dataset.theme ||
      (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    );
  }

  function paintButtons() {
    const dark = effectiveTheme() === 'dark';
    for (const btn of document.querySelectorAll('.theme-btn')) {
      btn.textContent = dark ? '☀️' : '🌙';
      btn.title = dark ? 'Switch to light mode' : 'Switch to dark mode';
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    paintButtons();
    for (const btn of document.querySelectorAll('.theme-btn')) {
      btn.addEventListener('click', () => {
        const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
        document.documentElement.dataset.theme = next;
        localStorage.setItem(KEY, next);
        paintButtons();
      });
    }
  });
})();
