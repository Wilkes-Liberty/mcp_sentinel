<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Form\FormBuilderInterface;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\Core\Url;
use Drupal\mcp_sentinel\Form\McpSealedTokenMintForm;
use Drupal\mcp_sentinel\Service\McpAdminStatus;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Reveal-once and revoke paths for sealed tokens.
 */
final class McpSealedTokenController extends ControllerBase {

  /**
   * Constructs the controller.
   */
  public function __construct(
    private readonly McpSealedTokenManager $tokens,
    private readonly McpAdminStatus $adminStatus,
    private readonly PrivateTempStoreFactory $tempStoreFactory,
    private readonly FormBuilderInterface $formBuilder,
    private readonly DateFormatterInterface $dateFormatter,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.sealed_token_manager'),
      $container->get('mcp_sentinel.admin_status'),
      $container->get('tempstore.private'),
      $container->get('form_builder'),
      $container->get('date.formatter'),
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
      'form' => $this->formBuilder->getForm(McpSealedTokenMintForm::class),
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
   * Shows the minted secret once, then forgets it.
   *
   * @return array
   *   Render array. The secret is gone after this request.
   */
  public function reveal(): array {
    $store = $this->tempStoreFactory->get('mcp_sentinel_sealed_token');
    $issued = $store->get('reveal');
    $store->delete('reveal');

    $build = [
      '#attached' => [
        'library' => ['mcp_sentinel/sealed_token', 'mcp_sentinel/admin'],
      ],
      'status' => [
        '#theme' => 'mcp_sentinel_status_strip',
        '#strip' => $this->adminStatus->build(),
      ],
    ];

    if (!is_array($issued) || !isset($issued['token']) || !is_string($issued['token'])) {
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

    $ttl = (int) ($issued['ttl'] ?? 0);
    $build['warning'] = [
      '#markup' => '<p><strong>' . $this->t('Copy this token now. It will not be shown again.') . '</strong> ' . $this->t('TTL: @ttl seconds. Client: @client. Leave this page and the secret is gone from the admin UI.', [
        '@ttl' => $ttl,
        '@client' => (string) ($issued['client_id'] ?? ''),
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

}
