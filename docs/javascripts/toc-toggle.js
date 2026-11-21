/* Desktop TOC disclosure. Mobile keeps the theme's native TOC controls. */
(() => {
  const storageKey = "pq-cp-abe:toc-collapsed";
  let collapsed = false;
  try {
    collapsed = localStorage.getItem(storageKey) === "true";
  } catch {
    // Private browsing/storage restrictions must not disable the control.
  }

  function installTocToggle() {
    const sidebar = document.querySelector(".md-sidebar--secondary");
    const nav = sidebar?.querySelector(".md-nav--secondary");
    const inner = sidebar?.querySelector(".md-sidebar__inner");
    if (!nav || !inner || sidebar.hidden || !nav.querySelector("a[href]")) return;
    if (document.querySelector(".pq-hero")) return;

    let button = inner.querySelector(".pq-toc-toggle");
    if (!button) {
      const header = document.createElement("div");
      header.className = "pq-toc-header";
      const title = document.createElement("span");
      title.className = "pq-toc-header__title";
      title.textContent = nav.getAttribute("aria-label") || "On this page";
      button = document.createElement("button");
      button.type = "button";
      button.className = "pq-page-tools__trigger pq-toc-toggle";
      button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m15 18-6-6 6-6"/></svg>';
      nav.id = "pq-toc-navigation";
      button.setAttribute("aria-controls", nav.id);
      header.append(title, button);
      inner.prepend(header);
      button.addEventListener("click", () => {
        collapsed = !collapsed;
        try {
          localStorage.setItem(storageKey, String(collapsed));
        } catch {
          // Retain the preference in memory for instant navigation.
        }
        update();
      });
    }

    function update() {
      sidebar.classList.add("pq-toc-ready");
      sidebar.classList.toggle("pq-toc-collapsed", collapsed);
      button.setAttribute("aria-expanded", String(!collapsed));
      const label = collapsed ? "Expand on this page" : "Collapse on this page";
      button.setAttribute("aria-label", label);
      button.title = label;
    }
    update();
  }

  if (typeof document$ !== "undefined") {
    document$.subscribe(installTocToggle);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", installTocToggle, { once: true });
  } else {
    installTocToggle();
  }
})();
