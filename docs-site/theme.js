// Light, dark or the device's mode. Loaded in <head> without defer so the saved
// choice applies before the first paint; the buttons are wired once the page is parsed.
(() => {
  const key = "hook-docs-theme";
  const root = document.documentElement;
  const read = () => {
    try {
      const saved = localStorage.getItem(key);
      return saved === "light" || saved === "dark" ? saved : "system";
    } catch {
      return "system";
    }
  };
  const apply = (choice) => {
    if (choice === "system") delete root.dataset.theme;
    else root.dataset.theme = choice;
    for (const button of document.querySelectorAll("[data-theme-choice]"))
      button.setAttribute("aria-pressed", String(button.dataset.themeChoice === choice));
  };
  apply(read());
  document.addEventListener("DOMContentLoaded", () => {
    apply(read());
    for (const button of document.querySelectorAll("[data-theme-choice]"))
      button.addEventListener("click", () => {
        const choice = button.dataset.themeChoice;
        try {
          if (choice === "system") localStorage.removeItem(key);
          else localStorage.setItem(key, choice);
        } catch {
          // Storage can be unavailable (private windows); the choice still applies to this page.
        }
        apply(choice);
      });
  });
})();
