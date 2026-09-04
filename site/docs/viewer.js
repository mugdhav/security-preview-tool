/* Renders one Markdown doc (site/docs/content/<DOC>.md) into the page.
   The .md files are the source of truth in docs/; the Pages workflow copies
   them (and docs/images/) into site/docs/content/ at deploy time. */
(function () {
  "use strict";

  var DOC = window.__DOC__;
  var SRC = "content/" + DOC + ".md";
  var GH = "https://github.com/mugdhav/security-preview-tool/blob/main/docs/";
  var MD_TO_PAGE = {
    DESKTOP: "desktop.html",
    USAGE: "cli.html",
    CURSOR: "skill.html",
    SKILL: "skill.html",
    README: "index.html"
  };

  var elDoc = document.getElementById("doc");
  var elToc = document.getElementById("toc");

  fetch(SRC)
    .then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.text();
    })
    .then(render)
    .catch(function (err) {
      elDoc.innerHTML =
        '<h1>Documentation</h1><p class="doc-status">Could not load <code>' +
        SRC + "</code> (" + String(err.message || err) +
        '). If you opened this file directly from disk, the browser blocks that read — ' +
        'view it on the <a href="' + GH + '">published site</a> or run a local web server ' +
        '(<code>python -m http.server</code>) from <code>site/</code>.</p>';
      if (elToc) elToc.closest(".toc").hidden = true;
    });

  function slugify(s) {
    return s.toLowerCase().replace(/[`~!@#$%^&*()+=<>?,./:;"'\[\]{}\\|]/g, "")
      .trim().replace(/\s+/g, "-");
  }

  function render(md) {
    marked.setOptions({ gfm: true, breaks: false });
    elDoc.innerHTML = marked.parse(md);
    rewriteLinks();
    buildToc();
    addCopyButtons();
    jumpToHash();
  }

  function rewriteLinks() {
    elDoc.querySelectorAll('img[src]').forEach(function (img) {
      var s = img.getAttribute("src");
      if (/^images\//.test(s)) img.setAttribute("src", "content/" + s);
    });
    elDoc.querySelectorAll('a[href]').forEach(function (a) {
      var h = a.getAttribute("href");
      var m = /^(?:\.\/)?([A-Za-z]+)\.md(#.*)?$/.exec(h);
      if (m && MD_TO_PAGE[m[1]]) a.setAttribute("href", MD_TO_PAGE[m[1]] + (m[2] || ""));
    });
  }

  function buildToc() {
    if (!elToc) return;
    var heads = elDoc.querySelectorAll("h2, h3");
    if (!heads.length) { elToc.closest(".toc").hidden = true; return; }
    var seen = {};
    heads.forEach(function (h) {
      var base = slugify(h.textContent) || "section";
      var id = base, n = 2;
      while (seen[id]) id = base + "-" + n++;
      seen[id] = true;
      h.id = id;
      var a = document.createElement("a");
      a.href = "#" + id;
      a.textContent = h.textContent;
      a.className = "lvl-" + h.tagName.charAt(1);
      elToc.appendChild(a);
    });
    var links = elToc.querySelectorAll("a");
    if (!("IntersectionObserver" in window)) return;
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        links.forEach(function (l) {
          l.classList.toggle("active", l.getAttribute("href") === "#" + e.target.id);
        });
      });
    }, { rootMargin: "0px 0px -78% 0px" });
    heads.forEach(function (h) { obs.observe(h); });
  }

  function addCopyButtons() {
    if (!navigator.clipboard) return;
    elDoc.querySelectorAll("pre").forEach(function (pre) {
      var code = pre.querySelector("code");
      var text = (code || pre).innerText;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = "Copy";
      btn.addEventListener("click", function () {
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = "Copied";
          btn.classList.add("ok");
          setTimeout(function () {
            btn.textContent = "Copy";
            btn.classList.remove("ok");
          }, 1400);
        });
      });
      pre.appendChild(btn);
    });
  }

  function jumpToHash() {
    if (!location.hash) return;
    var t = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (t) t.scrollIntoView();
  }
})();
