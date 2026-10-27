function unsafe(input, element) {
  // ruleid: ENGINE-JS-EVAL
  eval(input);
  // ruleid: ENGINE-JS-HTML
  element.innerHTML = input;
}
function safe(input, element) {
  // ok: ENGINE-JS-EVAL
  JSON.parse(input);
  // ok: ENGINE-JS-HTML
  element.textContent = input;
}
