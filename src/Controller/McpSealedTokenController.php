<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\TempStore\PrivateTempStore;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\Core\Url;
use Drupal\mcp_sentinel\EventSubscriber\McpSealedTokenRevealCsrfDenySubscriber;
use Drupal\mcp_sentinel\Form\McpSealedTokenMintForm;
use Drupal\mcp_sentinel\Service\McpAdminStatus;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Reveal-once and revoke paths for sealed tokens.
 */
final class McpSealedTokenController extends ControllerBase {

  /**
   * Constructs the controller.
   *
   * @param \Drupal\mcp_sentinel\Service\McpSealedTokenManager $tokens
   *   Sealed token manager.
   * @param \Drupal\mcp_sentinel\Service\McpAdminStatus $adminStatus
   *   Admin status strip assembler.
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory $tempStoreFactory
   *   Reveal tempstore. Its expire is McpSealedTokenManager::REVEAL_STORE_TTL.
   * @param \Drupal\Core\Datetime\DateFormatterInterface $dateFormatter
   *   Date formatter for the listing table.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Writes sealed_token_reveal through logAlways() when the secret
   *   is actually shown.
   */
  public function __construct(
    private readonly McpSealedTokenManager $tokens,
    private readonly McpAdminStatus $adminStatus,
    private readonly PrivateTempStoreFactory $tempStoreFactory,
    private readonly DateFormatterInterface $dateFormatter,
    private readonly McpAuditLogger $auditLogger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.sealed_token_manager'),
      $container->get('mcp_sentinel.admin_status'),
      $container->get('mcp_sentinel.sealed_token_reveal_store'),
      $container->get('date.formatter'),
      // Reveal audit is always written after a CSRF-valid POST shows
      // the secret. CSRF 403s are written by the deny subscriber.
      $container->get('mcp_sentinel.audit_logger'),
    );
  }

  /**
   * Mint form plus revoke table. Secrets are never listed.
   *
   * @return array
   *   Page render array.
   */
  public function listing(): array {
    $rows = [];
    foreach ($this->tokens->list() as $token) {
      $state = $token['revoked']
        ? $this->t('Revoked')
        : ($token['expired'] ? $this->t('Expired') : $this->t('Active'));
      $revoke = ($token['revoked'] || $token['expired'])
        ? ['data' => ['#markup' => '—']]
        : [
          'data' => [
            '#type' => 'link',
            '#title' => $this->t('Revoke'),
            '#url' => Url::fromRoute('mcp_sentinel.sealed_token_revoke', [
              'jti' => $token['jti'],
            ]),
          ],
        ];
      $rows[] = [
        $token['jti'],
        $token['client_id'],
        $token['scopes'] !== '' ? $token['scopes'] : '—',
        $this->dateFormatter->format($token['expires'], 'short'),
        $state,
        $revoke,
      ];
    }

    return [
      '#attached' => [
        'library' => ['mcp_sentinel/admin'],
      ],
      'status' => [
        '#theme' => 'mcp_sentinel_status_strip',
        '#strip' => $this->adminStatus->build(),
      ],
      'help' => [
        '#markup' => '<p>' . $this->t('Mint a short-lived sealed token bound to a designated agent client. The secret is shown once, then forgotten. Revoke immediately if it leaks. This is not an OAuth login flow.') . '</p>',
      ],
      'form' => $this->formBuilder()->getForm(McpSealedTokenMintForm::class),
      'table' => [
        '#type' => 'table',
        '#header' => [
          $this->t('Id'),
          $this->t('Client'),
          $this->t('Scopes'),
          $this->t('Expires'),
          $this->t('State'),
          $this->t('Operations'),
        ],
        '#rows' => $rows,
        '#empty' => $this->t('No sealed tokens have been minted.'),
        '#caption' => $this->t('Minted tokens (hash only — the secret is never stored or listed)'),
      ],
    ];
  }

  /**
   * GET landing after mint: offers a CSRF POST, never shows the secret.
   *
   * Peeking the tempstore does not delete the handoff. A refresh or
   * prefetch of this path must not echo or burn the plaintext.
   *
   * @return array
   *   Prompt or gone render array. The secret is never in this response.
   */
  public function revealPrompt(): array {
    $build = $this->revealShell(FALSE);
    // GET only looks. Delete happens on the CSRF-protected POST.
    if ($this->issuedPayload($this->revealStore()->get('reveal')) === NULL) {
      return $this->goneBuild($build);
    }

    $build['help'] = [
      '#markup' => '<p>' . $this->t(
        'The sealed token is ready. Show it once. Refreshing this page does not reveal the secret.',
      ) . '</p>',
    ];
    // Url::fromRoute() appends ?token= because the POST route requires
    // _csrf_token. A form without that query string is 403 and reveals
    // nothing.
    $action = Url::fromRoute(McpSealedTokenRevealCsrfDenySubscriber::ROUTE)
      ->toString();
    $build['reveal'] = [
      '#type' => 'inline_template',
      '#template' => '<form method="post" action="{{ action }}">'
        . '<button type="submit" class="button button--primary">'
        . '{{ label }}</button></form>',
      '#context' => [
        'action' => $action,
        'label' => $this->t('Show sealed token'),
      ],
    ];
    $build['back'] = [
      '#type' => 'link',
      '#title' => $this->t('Back to sealed tokens'),
      '#url' => Url::fromRoute('mcp_sentinel.sealed_token'),
    ];
    return $build;
  }

  /**
   * Shows the minted secret once, then forgets it.
   *
   * The route is POST plus _csrf_token. A missing or bad token is 403
   * before this method runs, so the tempstore key is left untouched.
   * That 403 writes sealed_token_reveal_denied (csrf_invalid).
   *
   * @return array
   *   Render array. The secret is gone from tempstore after this request.
   */
  public function reveal(): array {
    $store = $this->revealStore();
    // Consume first so a second valid POST cannot echo the same secret.
    $issued = $this->issuedPayload($store->get('reveal'));
    $store->delete('reveal');
    if ($issued === NULL) {
      return $this->goneBuild($this->revealShell(FALSE));
    }
    $build = $this->revealShell(TRUE);

    // Never store the bearer. jti and client_id are enough to pair this
    // row with the earlier sealed_token_mint entry. Disclosure is always
    // written, including when audit_enabled is off.
    $this->auditLogger->logAlways('sealed_token_reveal', [
      'jti' => $issued['jti'],
      'client_id' => $issued['client_id'],
      'ttl' => $issued['ttl'],
    ]);

    $build['warning'] = [
      '#markup' => '<p><strong>' . $this->t('Copy this token now. It will not be shown again.') . '</strong> ' . $this->t('TTL: @ttl seconds. Client: @client. Leave this page and the secret is gone from the admin UI.', [
        '@ttl' => $issued['ttl'],
        '@client' => $issued['client_id'],
      ]) . '</p>',
    ];
    $build['token'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Sealed token'),
      '#value' => $issued['token'],
      '#attributes' => [
        'readonly' => 'readonly',
        'class' => ['mcp-sealed-token__secret'],
        'data-mcp-sealed-token' => '1',
      ],
      '#rows' => 4,
    ];
    $build['copy'] = [
      '#type' => 'html_tag',
      '#tag' => 'button',
      '#value' => $this->t('Copy once'),
      '#attributes' => [
        'type' => 'button',
        'class' => ['button', 'button--primary', 'mcp-sealed-token__copy'],
      ],
    ];
    $build['back'] = [
      '#type' => 'link',
      '#title' => $this->t('Done — hide this secret'),
      '#url' => Url::fromRoute('mcp_sentinel.sealed_token'),
      '#attributes' => ['class' => ['button']],
    ];
    return $build;
  }

  /**
   * Revokes a minted token.
   */
  public function revoke(string $jti): RedirectResponse {
    if ($this->tokens->revoke($jti, $this->currentUser())) {
      $this->messenger()->addStatus($this->t('Sealed token @jti was revoked. The secret cannot be recovered.', [
        '@jti' => $jti,
      ]));
    }
    else {
      $this->messenger()->addWarning($this->t('That sealed token was already revoked or was not found.'));
    }
    return $this->redirect('mcp_sentinel.sealed_token');
  }

  /**
   * Shared no-store shell for the prompt and the consume page.
   *
   * @param bool $withCopyLibrary
   *   TRUE to attach the copy-once helper. The prompt has no secret.
   *
   * @return array
   *   Base render array with cache headers and the admin status strip.
   */
  private function revealShell(bool $withCopyLibrary): array {
    $libraries = ['mcp_sentinel/admin'];
    if ($withCopyLibrary) {
      $libraries[] = 'mcp_sentinel/sealed_token';
    }
    return [
      '#cache' => [
        'max-age' => 0,
      ],
      '#attached' => [
        'library' => $libraries,
        'http_header' => [
          ['Cache-Control', 'private, no-store', TRUE],
        ],
      ],
      'status' => [
        '#theme' => 'mcp_sentinel_status_strip',
        '#strip' => $this->adminStatus->build(),
      ],
    ];
  }

  /**
   * Copy-once tempstore that holds the plaintext until POST or TTL.
   */
  private function revealStore(): PrivateTempStore {
    return $this->tempStoreFactory->get('mcp_sentinel_sealed_token');
  }

  /**
   * Returns the handoff when it still carries a string secret.
   *
   * @param mixed $issued
   *   Tempstore payload, or NULL when the key is gone.
   *
   * @return array{token: string, jti: string, client_id: string, ttl: int}|null
   *   The payload, or NULL when there is nothing to show.
   */
  private function issuedPayload(mixed $issued): ?array {
    if (!is_array($issued)
      || !isset($issued['token'])
      || !is_string($issued['token'])
      || $issued['token'] === '') {
      return NULL;
    }
    // Rebuild with typed keys. A mixed tempstore bag is not this shape.
    $jti = $issued['jti'] ?? '';
    $clientId = $issued['client_id'] ?? '';
    $ttl = $issued['ttl'] ?? 0;
    return [
      'token' => $issued['token'],
      'jti' => is_string($jti) ? $jti : '',
      'client_id' => is_string($clientId) ? $clientId : '',
      'ttl' => is_numeric($ttl) ? (int) $ttl : 0,
    ];
  }

  /**
   * Explains that the secret is gone and links back to the mint listing.
   *
   * @param array $build
   *   Reveal shell render array.
   *
   * @return array
   *   Gone page. Must not include the bearer.
   */
  private function goneBuild(array $build): array {
    $build['gone'] = [
      '#markup' => '<p>' . $this->t('The sealed token is no longer shown. It was copy-once: refresh, navigation, or a second visit does not echo the secret. Revoke the token and mint a new one if you lost it.') . '</p>',
    ];
    $build['back'] = [
      '#type' => 'link',
      '#title' => $this->t('Back to sealed tokens'),
      '#url' => Url::fromRoute('mcp_sentinel.sealed_token'),
    ];
    return $build;
  }

}
