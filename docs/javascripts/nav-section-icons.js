function installSectionNavIcons() {
  const primaryNav = document.querySelector(".md-nav--primary");
  if (!primaryNav) return;

  const sectionItems = primaryNav.querySelectorAll(
    ".md-nav__item.md-nav__item--nested"
  );

  sectionItems.forEach((item) => {
    const label = item.querySelector(":scope > label.md-nav__link");
    if (!label || label.querySelector(".pq-section-nav-icon")) return;

    const nestedNav = item.querySelector(":scope > nav.md-nav");
    const sourceIcon = nestedNav?.querySelector(
      ".md-nav__list > .md-nav__item > .md-nav__link > svg"
    );
    const text = label.querySelector(".md-ellipsis");

    if (!sourceIcon || !text) return;

    const icon = sourceIcon.cloneNode(true);
    icon.classList.add("pq-section-nav-icon");
    icon.setAttribute("aria-hidden", "true");
    label.insertBefore(icon, text);
  });
}

if (typeof document$ !== "undefined") {
  document$.subscribe(installSectionNavIcons);
} else if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", installSectionNavIcons, { once: true });
} else {
  installSectionNavIcons();
}
