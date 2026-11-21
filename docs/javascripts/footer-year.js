function updateProjectYear() {
  const target = document.getElementById("pq-current-year");
  if (target) {
    target.textContent = String(new Date().getFullYear());
  }
}

if (typeof document$ !== "undefined") {
  document$.subscribe(updateProjectYear);
} else if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", updateProjectYear, { once: true });
} else {
  updateProjectYear();
}
