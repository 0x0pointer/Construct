(function () {
  "use strict";

  var pendingTargets = new Map();

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn, { once: true });
      return;
    }
    fn();
  }

  function localUrl(url) {
    var resolved = new URL(url || window.location.href, window.location.href);
    if (resolved.origin !== window.location.origin) {
      throw new Error("cross-origin url refused");
    }
    return resolved;
  }

  function formTarget(form) {
    var targetId = form.dataset.target;
    return targetId ? document.getElementById(targetId) : null;
  }

  function updateFormFromLocation(form) {
    var params = new URLSearchParams(window.location.search);
    Array.prototype.forEach.call(form.elements, function (field) {
      if (!field.name || field.disabled) {
        return;
      }
      if (field.type === "radio") {
        field.checked = params.get(field.name) === field.value;
        return;
      }
      field.value = params.get(field.name) || "";
    });
  }

  function replaceTarget(target, html) {
    target.innerHTML = html;
  }

  function beginTargetRequest(targetId) {
    var previous = pendingTargets.get(targetId);
    if (previous && previous.controller) {
      previous.controller.abort();
    }
    var next = { id: (previous ? previous.id : 0) + 1, controller: new AbortController() };
    pendingTargets.set(targetId, next);
    return next;
  }

  async function submitAsyncForm(form, config) {
    var optionsConfig = config || {};
    var target = formTarget(form);
    if (!target) {
      return;
    }
    var targetId = target.id;
    var request = beginTargetRequest(targetId);
    var method = (form.method || "get").toUpperCase();
    var action = localUrl(form.action || window.location.href);
    var fetchUrl = action;
    var options = {
      method: method,
      headers: { "HX-Request": "true", "HX-Target": targetId },
      signal: request.controller.signal,
    };

    if (method === "GET") {
      fetchUrl.search = new URLSearchParams(new FormData(form)).toString();
    } else {
      options.body = new FormData(form);
    }

    try {
      var response = await fetch(fetchUrl.toString(), options);
      if (!response.ok) {
        return;
      }
      var latest = pendingTargets.get(targetId);
      if (!latest || latest.id !== request.id) {
        return;
      }
      replaceTarget(target, await response.text());
      if (method === "GET" && form.dataset.history === "push" && optionsConfig.pushHistory !== false) {
        window.history.pushState({ targetId: targetId }, "", fetchUrl.pathname + fetchUrl.search);
      }
    } catch (error) {
      if (!error || error.name !== "AbortError") {
        window.console.error(error);
      }
    }
  }

  function appendUniqueChildren(target, source) {
    Array.prototype.forEach.call(source.children, function (child) {
      var eventId = child.getAttribute("data-id");
      if (eventId && target.querySelector('[data-id="' + CSS.escape(eventId) + '"]')) {
        return;
      }
      target.appendChild(child.cloneNode(true));
    });
  }

  function applyOutOfBandSwap(root) {
    Array.prototype.forEach.call(root.querySelectorAll("[hx-swap-oob]"), function (node) {
      var instruction = node.getAttribute("hx-swap-oob") || "";
      if (instruction === "delete") {
        if (node.id) {
          var doomed = document.getElementById(node.id);
          if (doomed) {
            doomed.remove();
          }
        }
        return;
      }
      var parts = instruction.split(":");
      if (parts.length !== 2 || parts[0] !== "beforeend") {
        return;
      }
      var target = document.querySelector(parts[1]);
      if (!target) {
        return;
      }
      appendUniqueChildren(target, node);
    });
  }

  async function pollTimeline(poller) {
    if (!poller || !poller.dataset.pollUrl) {
      return;
    }
    try {
      var response = await fetch(localUrl(poller.dataset.pollUrl).toString(), { headers: { "HX-Request": "true" } });
      if (!response.ok) {
        throw new Error("poll failed");
      }
      var parser = new DOMParser();
      var doc = parser.parseFromString(await response.text(), "text/html");
      applyOutOfBandSwap(doc);
      var nextPoller = doc.getElementById("timeline-poller");
      if (nextPoller && poller.isConnected) {
        poller.replaceWith(nextPoller);
        setupPoller(nextPoller);
      }
    } catch (error) {
      window.setTimeout(function () {
        setupPoller(poller);
      }, Number(poller.dataset.pollInterval || 2000));
    }
  }

  function setupPoller(poller) {
    if (!poller || !poller.dataset.pollUrl || poller.dataset.bound === "true") {
      return;
    }
    poller.dataset.bound = "true";
    window.setTimeout(function () {
      if (poller.isConnected) {
        pollTimeline(poller);
      }
    }, Number(poller.dataset.pollInterval || 2000));
  }

  ready(function () {
    document.documentElement.classList.add("js");

    document.addEventListener("submit", function (event) {
      var form = event.target.closest("form[data-async-form]");
      if (!form) {
        return;
      }
      event.preventDefault();
      submitAsyncForm(form);
    });

    document.addEventListener("change", function (event) {
      var form = event.target.closest('form[data-async-form][method="get"]');
      if (!form) {
        return;
      }
      submitAsyncForm(form);
    });

    window.addEventListener("popstate", function () {
      var form = document.querySelector('form[data-async-form][data-history="push"]');
      if (!form) {
        return;
      }
      updateFormFromLocation(form);
      submitAsyncForm(form, { pushHistory: false });
    });

    Array.prototype.forEach.call(document.querySelectorAll("#timeline-poller[data-poll-url]"), setupPoller);
  });
})();
