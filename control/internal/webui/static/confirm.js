// Confirmation dialogs for destructive actions. Inline onsubmit="return
// confirm(...)" handlers are blocked by the strict CSP (script-src has no
// unsafe-inline and nonces do not apply to inline event handlers), so the
// confirmation must be attached from a nonce-loaded script instead. A form
// opts in with a data-confirm="message" attribute.
(function () {
  document.addEventListener(
    "submit",
    function (e) {
      var f = e.target;
      if (f && f.matches && f.matches("form[data-confirm]")) {
        if (!window.confirm(f.getAttribute("data-confirm"))) {
          e.preventDefault();
        }
      }
    },
    true
  );
})();
