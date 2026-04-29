"use strict";
// Ticks the [data-due] element's countdown once a second. Server emits the
// absolute due time in Unix seconds; no server round-trip.
(function () {
  var el = document.querySelector(".countdown");
  if (!el) return;
  var head = el.querySelector(".countdown-headline");
  var due = parseInt(el.getAttribute("data-due"), 10) * 1000;
  if (!due) return;

  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function render() {
    var ms = due - Date.now();
    var abs = Math.abs(ms);
    var d = Math.floor(abs / 86400000);
    var h = Math.floor((abs % 86400000) / 3600000);
    var m = Math.floor((abs % 3600000) / 60000);
    var s = Math.floor((abs % 60000) / 1000);
    var prefix = ms < 0 ? "Overdue by " : "";
    var body;
    if (d > 0)      body = d + "d " + pad(h) + "h " + pad(m) + "m";
    else if (h > 0) body = pad(h) + ":" + pad(m) + ":" + pad(s);
    else            body = pad(m) + ":" + pad(s);
    head.textContent = prefix + body;
  }
  render();
  setInterval(render, 1000);
})();
