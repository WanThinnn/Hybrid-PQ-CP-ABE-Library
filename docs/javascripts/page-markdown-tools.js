let pqMarkdownPageMapPromise = null;
const pqMarkdownTextCache = new Map();

function pqDocsRootUrl() {
  const logo = document.querySelector(".md-header .md-logo");
  if (logo?.href) return new URL(logo.href, window.location.href);
  return new URL("./", window.location.href);
}

function pqCurrentPageRoute(rootUrl) {
  let pathname = decodeURIComponent(window.location.pathname);
  const rootPath = decodeURIComponent(rootUrl.pathname);

  if (pathname.startsWith(rootPath)) pathname = pathname.slice(rootPath.length);

  pathname = pathname
    .replace(/^\/+/, "")
    .replace(/index\.html$/, "")
    .replace(/\/+$/, "");

  return pathname ? pathname + "/" : "";
}

async function pqMarkdownPageMap(rootUrl) {
  if (!pqMarkdownPageMapPromise) {
    const mapUrl = new URL("assets/meta/markdown-pages.json", rootUrl);
    pqMarkdownPageMapPromise = fetch(mapUrl, { cache: "no-cache" }).then((response) => {
      if (!response.ok) throw new Error("Markdown page map is unavailable");
      return response.json();
    });
  }
  return pqMarkdownPageMapPromise;
}

async function pqFetchMarkdown(rawUrl) {
  const key = rawUrl.href;
  if (!pqMarkdownTextCache.has(key)) {
    pqMarkdownTextCache.set(
      key,
      fetch(rawUrl, { cache: "no-cache" }).then((response) => {
        if (!response.ok) throw new Error("Markdown source is unavailable");
        return response.text();
      })
    );
  }
  return pqMarkdownTextCache.get(key);
}

async function pqCopyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Clipboard copy failed");
}

function pqToolIcon(name) {
  const icons = {
    menu: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="5" cy="12" r="1.35"/><circle cx="12" cy="12" r="1.35"/><circle cx="19" cy="12" r="1.35"/></svg>',
    copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>',
    download: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/></svg>',
    raw: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="m10 13-2 2 2 2"/><path d="m14 13 2 2-2 2"/></svg>',
  };
  return icons[name] || "";
}

function pqCreateMenuItem({ icon, label, title, tag = "button" }) {
  const element = document.createElement(tag);
  element.className = "pq-page-tools__item";
  element.title = title;
  element.setAttribute("aria-label", title);
  element.setAttribute("role", "menuitem");

  if (tag === "button") element.type = "button";

  element.innerHTML =
    pqToolIcon(icon) +
    '<span class="pq-page-tools__item-label">' + label + "</span>";

  return element;
}

async function installMarkdownPageTools() {
  document.querySelectorAll("[data-pq-page-tools-menu]").forEach((node) => node.remove());

  const content = document.querySelector(".md-content__inner.md-typeset");
  if (!content || content.querySelector(".pq-page-tools")) return;

  const rootUrl = pqDocsRootUrl();
  const route = pqCurrentPageRoute(rootUrl);

  // The landing page intentionally stays clean; Markdown tools are for docs pages.
  if (route === "") return;

  let pageMap;
  try {
    pageMap = await pqMarkdownPageMap(rootUrl);
  } catch {
    return;
  }

  const page = pageMap[route];
  if (!page) return;

  const rawUrl = new URL(page.raw, rootUrl);

  const tools = document.createElement("div");
  tools.className = "pq-page-tools";

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "pq-page-tools__trigger";
  trigger.title = "Page actions";
  trigger.setAttribute("aria-label", "Open page actions");
  trigger.setAttribute("aria-haspopup", "menu");
  trigger.setAttribute("aria-expanded", "false");
  trigger.innerHTML = pqToolIcon("menu");

  const menu = document.createElement("div");
  menu.className = "pq-page-tools__menu";
  menu.setAttribute("role", "menu");
  menu.setAttribute("data-pq-page-tools-menu", "");
  menu.hidden = true;

  const copy = pqCreateMenuItem({
    icon: "copy",
    label: "Copy Markdown for AI",
    title: "Copy this page as Markdown for an AI agent",
  });

  copy.addEventListener("click", async () => {
    const label = copy.querySelector(".pq-page-tools__item-label");
    const original = label?.textContent || "Copy Markdown for AI";

    try {
      copy.disabled = true;
      const markdown = await pqFetchMarkdown(rawUrl);
      await pqCopyText(markdown);
      copy.classList.add("pq-page-tools__item--success");
      if (label) label.textContent = "Copied";
      copy.title = "Markdown copied";

      setTimeout(() => {
        copy.classList.remove("pq-page-tools__item--success");
        copy.disabled = false;
        if (label) label.textContent = original;
        copy.title = "Copy this page as Markdown for an AI agent";
      }, 1400);
    } catch {
      copy.disabled = false;
      copy.title = "Could not copy Markdown";
    }
  });

  const download = pqCreateMenuItem({
    icon: "download",
    label: "Download",
    title: "Download this page as Markdown",
    tag: "a",
  });
  download.href = rawUrl.href;
  download.download = page.filename;

  const raw = pqCreateMenuItem({
    icon: "raw",
    label: "View raw Markdown",
    title: "Open raw Markdown",
    tag: "a",
  });
  raw.href = rawUrl.href;
  raw.target = "_blank";
  raw.rel = "noopener";

  menu.append(copy, download, raw);
  tools.append(trigger);
  document.body.append(menu);

  const positionMenu = () => {
    if (menu.hidden) return;

    const rect = trigger.getBoundingClientRect();
    const viewportPadding = 8;
    const gap = 7;
    const width = menu.offsetWidth;
    const height = menu.offsetHeight;

    let left = rect.right - width;
    left = Math.max(viewportPadding, Math.min(left, window.innerWidth - width - viewportPadding));

    let top = rect.bottom + gap;
    if (top + height > window.innerHeight - viewportPadding) {
      const above = rect.top - height - gap;
      if (above >= viewportPadding) top = above;
    }

    menu.style.left = Math.round(left) + "px";
    menu.style.top = Math.round(top) + "px";
  };

  const setOpen = (open) => {
    tools.classList.toggle("pq-page-tools--open", open);
    trigger.setAttribute("aria-expanded", String(open));
    menu.hidden = !open;

    if (open) positionMenu();
  };

  trigger.addEventListener("click", (event) => {
    event.stopPropagation();
    setOpen(menu.hidden);
  });

  menu.addEventListener("click", (event) => {
    event.stopPropagation();
  });

  document.addEventListener("click", () => setOpen(false));
  window.addEventListener("resize", positionMenu);
  window.addEventListener("scroll", positionMenu, { passive: true });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !menu.hidden) {
      setOpen(false);
      trigger.focus();
    }
  });

  const contentShell = content.closest(".md-content");
  const breadcrumb = contentShell?.querySelector(":scope > .md-path");

  if (breadcrumb) {
    breadcrumb.classList.add("pq-page-context-row");
    breadcrumb.append(tools);
  } else {
    const anchor = content.querySelector("h1");
    if (anchor) anchor.before(tools);
    else content.prepend(tools);
  }
}

if (typeof document$ !== "undefined") {
  document$.subscribe(() => {
    void installMarkdownPageTools();
  });
} else if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    () => {
      void installMarkdownPageTools();
    },
    { once: true }
  );
} else {
  void installMarkdownPageTools();
}
