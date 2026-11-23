// The chat page's message box: Enter sends the message and Shift+Enter adds a new line. On a
// touch screen, whose primary pointer is coarse, Enter keeps adding a new line, because the
// on-screen keyboard has no easy Shift+Enter and the Send button is under the thumb. The script
// marks the page `enter-sends` while a keyboard is the way to type, which is what shows the hint
// next to the Send button, and points the message box's `aria-describedby` at the hint then too, so
// a screen reader announces the shortcut where the user types. Without this script Enter adds a new
// line, the hint stays hidden, and Send works as before.
(function () {
  'use strict';

  var touch = window.matchMedia('(pointer: coarse)');

  function update() {
    var sends = !touch.matches;
    document.documentElement.classList.toggle('enter-sends', sends);
    // The hint is hidden when Enter doesn't send, and a screen reader would still read it.
    var box = document.querySelector('#compose textarea');
    if (box) {
      if (sends) {
        box.setAttribute('aria-describedby', 'compose-hint');
      } else {
        box.removeAttribute('aria-describedby');
      }
    }
  }
  update();
  if (touch.addEventListener) {
    touch.addEventListener('change', update);
  }
  // This script runs before the page body exists, and htmx replaces the form after every post;
  // `htmx:load` fires for the page and for each swapped-in fragment.
  document.addEventListener('htmx:load', update);

  // The compose form replaces itself after every post, so the listener sits on the document.
  document.addEventListener('keydown', function (event) {
    var box = event.target;
    if (
      event.key !== 'Enter' ||
      event.shiftKey ||
      event.ctrlKey ||
      event.altKey ||
      event.metaKey ||
      // Safari ends the composition before the Enter that confirms it, with keyCode 229.
      event.isComposing ||
      event.keyCode === 229 ||
      touch.matches ||
      !box.matches('#compose textarea')
    ) {
      return;
    }
    // Enter never adds a line here, so a second press during a post can't send the text twice.
    event.preventDefault();
    var form = box.form;
    if (form && !form.classList.contains('htmx-request')) {
      form.requestSubmit();
    }
  });
})();
