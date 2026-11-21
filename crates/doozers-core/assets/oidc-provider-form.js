// The new identity provider form (/admin/identity-providers/new): fills the Redirect URI field from
// the Id field as the admin types, so the URI to register at the provider is the real one. Until the
// Id is valid the field shows `<id>` in its place. Without this script the form still works: the
// field shows the URI with `<id>`, or with the typed id when the form comes back after an error.
//
// `valid` must stay equal to `is_provider_id` in crates/doozers-store/src/oidc.rs: 1 to 32
// characters of a-z, 0-9 and hyphen, not starting with a hyphen.
(function () {
  'use strict';

  var id = document.getElementById('id');
  var redirect = document.getElementById('redirect');
  if (!id || !redirect || !redirect.hasAttribute('data-template')) {
    return;
  }
  var template = redirect.getAttribute('data-template');

  function valid(text) {
    return /^[a-z0-9][a-z0-9-]{0,31}$/.test(text);
  }

  function update() {
    var typed = id.value.trim();
    redirect.value = template.replace('<id>', valid(typed) ? typed : '<id>');
  }

  id.addEventListener('input', update);
  update();
})();
