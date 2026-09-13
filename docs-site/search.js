const input = document.querySelector("#search"),
  results = document.querySelector("#search-results");
let index;
input.addEventListener("input", async () => {
  const query = input.value.trim().toLowerCase();
  if (query.length < 2) {
    results.hidden = true;
    return;
  }
  try {
    index ||= fetch("/search-index.json").then((r) => {
      if (!r.ok) throw new Error("Search unavailable");
      return r.json();
    });
    const pages = await index;
    if (query !== input.value.trim().toLowerCase()) return;
    const terms = query.split(/\s+/);
    const matches = pages
      .map((p) => ({
        ...p,
        rank: terms.reduce(
          (n, t) =>
            n +
            (p.title.toLowerCase().includes(t) ? 10 : 0) +
            (p.text.toLowerCase().includes(t) ? 1 : 0),
          0,
        ),
      }))
      .filter((p) => terms.every((t) => (p.title + " " + p.text).toLowerCase().includes(t)))
      .sort((a, b) => b.rank - a.rank)
      .slice(0, 10);
    results.replaceChildren();
    for (const page of matches) {
      const link = document.createElement("a");
      link.href = page.url;
      const title = document.createElement("strong");
      title.textContent = page.title;
      const excerpt = document.createElement("p");
      const offset = Math.max(0, page.text.toLowerCase().indexOf(terms[0]) - 60);
      excerpt.textContent = page.text.slice(offset, offset + 210) + "…";
      link.append(title, excerpt);
      results.append(link);
    }
    if (!matches.length) {
      const note = document.createElement("p");
      note.textContent = "No matching pages. Try a permission, command, or endpoint name.";
      results.append(note);
    }
    results.hidden = false;
  } catch {
    index = null;
    results.textContent = "Search is unavailable. Use the navigation to browse the guides.";
    results.hidden = false;
  }
});
input.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    results.hidden = true;
    input.blur();
  } else if (e.key === "ArrowDown" && !results.hidden) {
    e.preventDefault();
    results.querySelector("a")?.focus();
  }
});
document.addEventListener("click", (e) => {
  if (!results.contains(e.target) && e.target !== input) results.hidden = true;
});
