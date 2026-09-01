// Must-NOT-detect: text assignment and sanitised HTML.
function render(userInput) {
  document.getElementById("out").textContent = userInput;
}

function safeHtml(userInput) {
  el.innerHTML = DOMPurify.sanitize(userInput);
}
