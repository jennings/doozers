// The copy buttons of the SSH keys page: a button with `data-copy-from="<id>"` copies the value of
// the field with that id. The button is an icon attached to the field; after a copy it shows a
// check mark and says "Copied" to assistive technology for a moment. Without this script the
// buttons stay hidden and the page still works: the field is read-only text to select and copy by
// hand.
(function () {
  'use strict';

  document.querySelectorAll('button[data-copy-from]').forEach(function (button) {
    var field = document.getElementById(button.getAttribute('data-copy-from'));
    if (!field) {
      return;
    }
    var label = button.getAttribute('aria-label');
    var timer = null;
    button.hidden = false;
    button.addEventListener('click', function () {
      field.select();
      var done = function () {
        button.setAttribute('data-copied', '');
        button.setAttribute('aria-label', 'Copied');
        button.title = 'Copied';
        clearTimeout(timer);
        timer = setTimeout(function () {
          button.removeAttribute('data-copied');
          button.setAttribute('aria-label', label);
          button.title = label;
        }, 1500);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(field.value).then(done);
      } else if (document.execCommand('copy')) {
        done();
      }
    });
  });
})();
