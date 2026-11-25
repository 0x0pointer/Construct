"use strict";

(function () {
  const PARTIAL_REQUEST = "X-Partial-Request";
  const PARTIAL_TARGET = "X-Partial-Target";
  let timelineTimer = null;

  function parseFragment(html) {
    const template = document.createElement("template");
    template.innerHTML = html.trim();
    return template.content;
  }

  function setRegionContent(target, html) {
    const fragment = parseFragment(html);
    target.replaceChildren(fragment);
  }

  async function fetchText(url, options) {
    const response = await fetch(url, { credentials: "same-origin", ...options });
    if (!response.ok) {
      throw new Error(`Request failed with ${response.status}`);
    }
    return response.text();
  }

  function formUrl(form) {
    const url = new URL(form.getAttribute("action") || window.location.href, window.location.origin);
    const data = new FormData(form);
    url.search = "";
    for (const [key, value] of data.entries()) {
      if (typeof value === "string" && value !== "") {
        url.searchParams.append(key, value);
      }
    }
    return url;
  }

  function initFilters() {
    const form = document.querySelector("[data-dashboard-filters]");
    const targetId = form?.dataset.partialTarget;
    const target = targetId ? document.getElementById(targetId) : null;
    if (!form || !target) {
      return;
    }

    let requestId = 0;
    const submit = async () => {
      const url = formUrl(form);
      requestId += 1;
      const currentId = requestId;
      try {
        const html = await fetchText(url, {
          headers: {
            [PARTIAL_REQUEST]: "true",
            [PARTIAL_TARGET]: target.id,
          },
        });
        if (currentId !== requestId) {
          return;
        }
        history.replaceState({}, "", `${url.pathname}${url.search}` || "/findings");
        setRegionContent(target, html);
      } catch {
        form.submit();
      }
    };

    form.addEventListener("change", (event) => {
      if (event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement) {
        void submit();
      }
    });

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void submit();
    });
  }

  function initTriage() {
    const form = document.querySelector("[data-dashboard-triage]");
    const targetId = form?.dataset.partialTarget;
    const target = targetId ? document.getElementById(targetId) : null;
    if (!form || !target) {
      return;
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const html = await fetchText(form.action, {
          method: "POST",
          headers: {
            [PARTIAL_REQUEST]: "true",
            [PARTIAL_TARGET]: target.id,
          },
          body: new FormData(form),
        });
        setRegionContent(target, html);
        initTriage();
      } catch {
        form.submit();
      }
    });
  }

  function dedupeAppend(target, fragment) {
    const container = document.createElement("div");
    container.append(fragment.cloneNode(true));
    const children = Array.from(container.children).length
      ? Array.from(container.children)
      : Array.from(fragment.childNodes).filter((node) => node instanceof Element || node.textContent?.trim());

    for (const node of children) {
      if (!(node instanceof Element)) {
        target.append(node.cloneNode(true));
        continue;
      }
      const ids = node.hasAttribute("data-id")
        ? [node.getAttribute("data-id")]
        : Array.from(node.querySelectorAll("[data-id]")).map((item) => item.getAttribute("data-id"));
      if (ids.length && ids.every((id) => id && document.querySelector(`[data-id="${CSS.escape(id)}"]`))) {
        continue;
      }
      target.append(node.cloneNode(true));
    }
  }

  function applyTimelineResponse(html) {
    const fragment = parseFragment(html);

    for (const marker of fragment.querySelectorAll("[data-remove-target]")) {
      const target = document.querySelector(marker.getAttribute("data-remove-target"));
      target?.remove();
    }

    for (const replacement of fragment.querySelectorAll("[data-replace-target]")) {
      const target = document.querySelector(replacement.getAttribute("data-replace-target"));
      if (target) {
        target.replaceWith(replacement.cloneNode(true));
      }
    }

    for (const template of fragment.querySelectorAll("template[data-append-target]")) {
      const target = document.querySelector(template.getAttribute("data-append-target"));
      if (!target) {
        continue;
      }
      const content = template.content.cloneNode(true);
      const list = content.firstElementChild;
      dedupeAppend(target, list && list.tagName === "OL" ? list : content);
    }
  }

  async function pollTimeline() {
    const poller = document.querySelector("[data-dashboard-timeline-poller]");
    if (!poller || poller.dataset.live !== "true" || !poller.dataset.pollUrl) {
      return;
    }
    try {
      const html = await fetchText(poller.dataset.pollUrl, {
        headers: {
          [PARTIAL_REQUEST]: "true",
          [PARTIAL_TARGET]: "timeline",
        },
      });
      applyTimelineResponse(html);
    } catch {
      // Keep the manual reload fallback visible.
    } finally {
      scheduleTimeline();
    }
  }

  function scheduleTimeline() {
    if (timelineTimer !== null) {
      window.clearTimeout(timelineTimer);
      timelineTimer = null;
    }
    const poller = document.querySelector("[data-dashboard-timeline-poller]");
    if (!poller || poller.dataset.live !== "true" || !poller.dataset.pollUrl) {
      return;
    }
    const delay = Number.parseInt(poller.dataset.pollInterval || "2000", 10);
    timelineTimer = window.setTimeout(() => {
      timelineTimer = null;
      void pollTimeline();
    }, Number.isFinite(delay) ? delay : 2000);
  }

  function init() {
    initFilters();
    initTriage();
    scheduleTimeline();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
