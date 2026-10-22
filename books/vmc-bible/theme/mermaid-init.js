// Mermaid 다이어그램 렌더링. ```mermaid 코드 블록을 그림으로 바꾼다.
// mermaid.min.js(v11.4.1, MIT)는 같은 theme/ 디렉터리에 번들되어 있어 인트라넷에서도 동작한다.
(function () {
  var blocks = document.querySelectorAll("pre > code.language-mermaid");
  if (!blocks.length) return;
  blocks.forEach(function (code) {
    var pre = code.parentElement;
    var div = document.createElement("div");
    div.className = "mermaid";
    div.textContent = code.textContent;
    pre.replaceWith(div);
  });
  var dark = /navy|coal|ayu/.test(document.documentElement.className);
  function render() {
    mermaid.initialize({ startOnLoad: false, theme: dark ? "dark" : "default", securityLevel: "strict" });
    mermaid.run({ querySelector: ".mermaid" });
  }
  if (window.mermaid) { render(); return; }   // book.toml additional-js 로 이미 로드된 경우
  var self = document.currentScript && document.currentScript.src;
  var s = document.createElement("script");
  s.src = self ? self.replace(/mermaid-init\.js.*$/, "mermaid.min.js") : "theme/mermaid.min.js";
  s.onload = render;
  document.head.appendChild(s);
})();
