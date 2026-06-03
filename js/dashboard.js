/**
 * @file
 * Governance dashboard behaviors: per-user urgent-banner dismissal.
 *
 * Vanilla JS only. The window toggle is plain server-rendered links, so it
 * needs no script; this behavior only enhances banner dismissal by hiding the
 * banner and recording a per-user dismissal via the dismissal endpoint.
 */
((Drupal, drupalSettings, once) => {
  Drupal.behaviors.mcpSentinelDashboard = {
    attach(context) {
      once('mcp-banner-dismiss', '[data-mcp-banner-dismiss]', context).forEach(
        (button) => {
          button.addEventListener('click', () => {
            const banner = button.closest('[data-mcp-banner-key]');
            if (!banner) {
              return;
            }
            const key = banner.getAttribute('data-mcp-banner-key');
            const settings = drupalSettings.mcpSentinel || {};
            const url = settings.dismissUrl;
            // The dismiss URL already carries the per-session CSRF token; only
            // the condition key is sent in the request body.
            if (url && key) {
              const body = new URLSearchParams();
              body.append('key', key);
              fetch(url, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: body.toString(),
                credentials: 'same-origin',
              });
            }
            banner.parentNode.removeChild(banner);
          });
        },
      );
    },
  };
})(Drupal, drupalSettings, once);
