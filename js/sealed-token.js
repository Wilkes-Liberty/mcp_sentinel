/**
 * @file
 * Copy-once helper for the sealed-token reveal page.
 *
 * Copies the secret, then replaces the field so a later glance at the
 * same DOM cannot re-read it. The server already forgot the plaintext.
 */
((Drupal, once) => {
  Drupal.behaviors.mcpSealedTokenCopy = {
    attach(context) {
      once('mcp-sealed-token-copy', '.mcp-sealed-token__copy', context).forEach(
        (button) => {
          button.addEventListener('click', () => {
            const field = context.querySelector
              ? context.querySelector('[data-mcp-sealed-token]')
              : null;
            const secret = field && 'value' in field ? field.value : '';
            if (!secret || !navigator.clipboard) {
              return;
            }
            navigator.clipboard.writeText(secret).then(() => {
              if (field) {
                field.value = Drupal.t(
                  'Copied. This secret is no longer shown. Leave the page and it cannot be echoed.',
                );
                field.setAttribute('readonly', 'readonly');
                field.removeAttribute('data-mcp-sealed-token');
              }
              button.setAttribute('disabled', 'disabled');
              button.textContent = Drupal.t('Copied');
            });
          });
        },
      );
    },
  };
})(Drupal, once);
