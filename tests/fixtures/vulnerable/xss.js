// Must-detect: untrusted data written into the DOM.
function render(userInput) {
  document.getElementById("out").innerHTML = "<b>" + userInput + "</b>";
}

function greet(name) {
  el.innerHTML = `Hello ${name}`;
}
