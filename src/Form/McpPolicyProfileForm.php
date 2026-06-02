<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\Core\Entity\EntityForm;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Form\FormStateInterface;

/**
 * Add/edit form for an MCP policy profile.
 */
final class McpPolicyProfileForm extends EntityForm {

  /**
   * {@inheritdoc}
   */
  public function form(array $form, FormStateInterface $form_state): array {
    $form = parent::form($form, $form_state);
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile */
    $profile = $this->entity;

    // Attach the admin library (vertical-tabs CSS, preview styles).
    $form['#attached']['library'][] = 'mcp_sentinel/admin';

    // Vertical-tabs container. Children are details elements with #group.
    // Do NOT use #tree on any group — values remain flat so save()/
    // copyFormValuesToEntity() need no path changes.
    $form['tabs'] = [
      '#type' => 'vertical_tabs',
      '#default_tab' => 'edit-identity',
    ];

    // --- Identity tab --------------------------------------------------------
    $form['identity'] = [
      '#type' => 'details',
      '#title' => $this->t('Identity'),
      '#group' => 'tabs',
    ];
    $form['identity']['label'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Label'),
      '#default_value' => $profile->label(),
      '#required' => TRUE,
    ];
    $form['identity']['id'] = [
      '#type' => 'machine_name',
      '#default_value' => $profile->id(),
      '#machine_name' => [
        'exists' => '\Drupal\mcp_sentinel\Entity\McpPolicyProfile::load',
      ],
      '#disabled' => !$profile->isNew(),
    ];
    $form['identity']['status'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enabled'),
      '#description' => $this->t('Disabled profiles are ignored by the resolver; governed agents matching only a disabled profile fall back to the default.'),
      '#default_value' => $profile->status(),
    ];

    /** @var \Drupal\user\RoleInterface[] $roles */
    $roles = $this->entityTypeManager->getStorage('user_role')->loadMultiple();
    $role_options = [];
    foreach ($roles as $rid => $role) {
      $role_options[$rid] = (string) $role->label();
    }
    // anonymous/authenticated would govern all (or unauthenticated) traffic.
    unset($role_options['anonymous'], $role_options['authenticated']);

    $form['identity']['roles'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Roles'),
      '#description' => $this->t(
        'Apply this profile to agents holding any of these roles. Leave empty for the default profile that applies to every governed agent without a more specific match.'
      ),
      '#options' => $role_options,
      '#default_value' => $profile->getRoles(),
    ];
    $form['identity']['weight'] = [
      '#type' => 'number',
      '#title' => $this->t('Weight'),
      '#description' => $this->t(
        'Higher weight wins when multiple profiles match an agent.'
      ),
      '#default_value' => $profile->getWeight(),
    ];

    // Policy-preview placeholder (populated by buildPolicyPreview; also target
    // for the AJAX callback added in E2). Placed at the bottom of the Identity
    // tab so it is visible on initial load without switching tabs.
    $form['identity']['preview'] = $this->buildPolicyPreview($form_state);

    // --- Allowed operations tab ----------------------------------------------
    $form['gates'] = [
      '#type' => 'details',
      '#title' => $this->t('Allowed operations'),
      '#group' => 'tabs',
    ];
    foreach ([
      'allow_read' => $this->t('Allow read'),
      'allow_write' => $this->t('Allow write (create, update)'),
      'allow_delete' => $this->t('Allow delete'),
      'allow_graphql_mutations' => $this->t('Allow GraphQL mutations'),
    ] as $key => $label) {
      $form['gates'][$key] = [
        '#type' => 'checkbox',
        '#title' => $label,
        '#default_value' => $profile->get($key),
      ];
    }

    // --- Entity scope tab ----------------------------------------------------
    $lines = static fn (array $v): string => implode("\n", $v);
    $form['entity_scope'] = [
      '#type' => 'details',
      '#title' => $this->t('Entity scope'),
      '#group' => 'tabs',
    ];
    $form['entity_scope']['allowed_entity_types'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed entity types (empty = all)'),
      '#description' => $this->t('One machine name per line (e.g. node, taxonomy_term). Leave empty to allow all entity types not on the deny list.'),
      '#default_value' => $lines($profile->getAllowedEntityTypes()),
      '#rows' => 3,
    ];
    $form['entity_scope']['denied_entity_types'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Denied entity types'),
      '#description' => $this->t('One machine name per line. Governed reads and writes to these entity types are always blocked.'),
      '#default_value' => $lines($profile->getDeniedEntityTypes()),
      '#rows' => 3,
    ];

    // --- Redaction tab -------------------------------------------------------
    $form['redaction'] = [
      '#type' => 'details',
      '#title' => $this->t('Redaction'),
      '#group' => 'tabs',
    ];
    $form['redaction']['redacted_fields'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Redacted fields'),
      '#description' => $this->t('One field machine name per line. Values of these fields are replaced with *** in audit diffs and read responses.'),
      '#default_value' => $lines($profile->getRedactedFields()),
      '#rows' => 3,
    ];

    // --- Rate limits & quotas tab --------------------------------------------
    $form['limits'] = [
      '#type' => 'details',
      '#title' => $this->t('Rate limits & quotas'),
      '#group' => 'tabs',
    ];
    $form['limits']['rate_limit_requests'] = [
      '#type' => 'number',
      '#min' => 0,
      '#title' => $this->t('Max requests per window (0 = unlimited)'),
      '#description' => $this->t('Throttle governed agent traffic per account. 0 = unlimited. Recommended: 300.'),
      '#default_value' => $profile->getRateLimitRequests(),
    ];
    $form['limits']['rate_limit_window'] = [
      '#type' => 'number',
      '#min' => 1,
      '#title' => $this->t('Window (seconds)'),
      '#description' => $this->t('Rate-limit window length. Recommended: 60.'),
      '#default_value' => $profile->getRateLimitWindow() ?: 60,
      '#states' => [
        'visible' => [
          ':input[name="rate_limit_requests"]' => ['!value' => '0'],
        ],
      ],
    ];
    $form['limits']['result_count_cap'] = [
      '#type' => 'number',
      '#min' => 0,
      '#title' => $this->t('Max result items (0 = unlimited)'),
      // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
      '#description' => $this->t('Maximum items returned per Tool call, JSON:API page request, or GraphQL field result list. Recommended: 500.'),
      '#default_value' => $profile->getResultCountCap(),
    ];
    $form['limits']['response_size_cap'] = [
      '#type' => 'number',
      '#min' => 0,
      '#title' => $this->t('Max response size in bytes (0 = unlimited)'),
      // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
      '#description' => $this->t('Maximum serialized response size in bytes for governed Tool calls. Responses exceeding this cap are denied. Recommended: 2097152 (2 MB).'),
      '#default_value' => $profile->getResponseSizeCap(),
    ];

    // --- Network / IP tab ----------------------------------------------------
    $form['ip_allowlist'] = [
      '#type' => 'details',
      '#title' => $this->t('Network / IP'),
      '#group' => 'tabs',
    ];
    // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
    $ipDesc = $this->t('Enter one IPv4/IPv6 address or CIDR block per line (e.g. 203.0.113.0/24 or 2001:db8::/32). Leave empty to allow all source IPs (no restriction). IMPORTANT: IP enforcement reads the client IP via Symfony trusted-proxy-aware getClientIp(), which only honors X-Forwarded-For when the connecting proxy is listed in Drupal reverse_proxy_addresses. If your site sits behind a load balancer or CDN you MUST configure reverse_proxy = TRUE and reverse_proxy_addresses in settings.php; otherwise all requests will appear to come from the proxy IP.');
    $form['ip_allowlist']['allowed_ips'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed IPs / CIDRs (one per line, empty = all IPs allowed)'),
      '#description' => $ipDesc,
      '#default_value' => implode("\n", $profile->getAllowedIps()),
      '#rows' => 5,
    ];

    return $form;
  }

  /**
   * Builds the policy-preview render array from current form / entity values.
   *
   * On initial page load the values are read from the entity. On AJAX rebuilds
   * they are read from form_state. The preview is read-only and stores nothing.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current form state.
   *
   * @return array
   *   A render array with class .mcp-policy-preview.
   */
  protected function buildPolicyPreview(FormStateInterface $form_state): array {
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile */
    $profile = $this->entity;

    // On an AJAX rebuild use the current input values; on initial load fall
    // back to the entity. Values are present in form_state after first submit.
    $get = static function (string $key, mixed $default) use ($form_state): mixed {
      // getValue() returns NULL when the key was never submitted.
      $val = $form_state->getValue($key);
      return ($val !== NULL) ? $val : $default;
    };

    $read = (bool) $get('allow_read', $profile->get('allow_read'));
    $write = (bool) $get('allow_write', $profile->get('allow_write'));
    $delete = (bool) $get('allow_delete', $profile->get('allow_delete'));
    $graphql = (bool) $get('allow_graphql_mutations', $profile->get('allow_graphql_mutations'));

    $split = static fn (mixed $v): array => is_string($v)
      ? array_values(array_filter(array_map('trim', explode("\n", $v))))
      : (array) $v;

    $allowed_types = $split($get('allowed_entity_types', $profile->getAllowedEntityTypes()));
    $denied_types = $split($get('denied_entity_types', $profile->getDeniedEntityTypes()));
    $redacted = $split($get('redacted_fields', $profile->getRedactedFields()));
    $rate_req = (int) $get('rate_limit_requests', $profile->getRateLimitRequests());
    $rate_win = (int) $get('rate_limit_window', $profile->getRateLimitWindow() ?: 60);
    $result_cap = (int) $get('result_count_cap', $profile->getResultCountCap());
    $resp_cap = (int) $get('response_size_cap', $profile->getResponseSizeCap());
    $ips = $split($get('allowed_ips', $profile->getAllowedIps()));

    $yn = fn (bool $v): string => $v ? (string) $this->t('allowed') : (string) $this->t('denied');

    $items = [];
    $items[] = $this->t('Read: @v · Write: @v2 · Delete: @v3 · GraphQL mutations: @v4', [
      '@v' => $yn($read),
      '@v2' => $yn($write),
      '@v3' => $yn($delete),
      '@v4' => $yn($graphql),
    ]);

    $scope_allowed = empty($allowed_types)
      ? (string) $this->t('all types')
      : implode(', ', $allowed_types);
    $scope_denied = empty($denied_types)
      ? (string) $this->t('none')
      : implode(', ', $denied_types);
    $items[] = $this->t('Entity scope: allowed: @a; denied: @d', [
      '@a' => $scope_allowed,
      '@d' => $scope_denied,
    ]);

    $items[] = empty($redacted)
      ? $this->t('Redacted fields: none')
      : $this->t('Redacted fields: @f', ['@f' => implode(', ', $redacted)]);

    $rate_str = ($rate_req > 0)
      ? $this->t('@r req / @w s', ['@r' => $rate_req, '@w' => $rate_win])
      : $this->t('unlimited');
    $result_str = ($result_cap > 0) ? (string) $result_cap : (string) $this->t('unlimited');
    $resp_str = ($resp_cap > 0) ? (string) $resp_cap . ' B' : (string) $this->t('unlimited');
    $items[] = $this->t('Rate limit: @rate · Result cap: @rc · Response cap: @rsc', [
      '@rate' => $rate_str,
      '@rc' => $result_str,
      '@rsc' => $resp_str,
    ]);

    $ip_str = empty($ips)
      ? (string) $this->t('all IPs allowed')
      : $this->t('@n CIDR(s)', ['@n' => count($ips)]);
    $items[] = $this->t('IP allowlist: @v', ['@v' => $ip_str]);

    return [
      '#prefix' => '<div id="mcp-policy-preview-wrapper"><div class="mcp-policy-preview">',
      '#suffix' => '</div></div>',
      '#theme' => 'item_list',
      '#items' => $items,
      '#title' => $this->t('Effective policy summary (preview)'),
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);
    $raw = (string) $form_state->getValue('allowed_ips');
    $lines = array_values(array_filter(array_map('trim', explode("\n", $raw))));
    foreach ($lines as $line) {
      if (!$this->isValidIpOrCidr($line)) {
        $form_state->setErrorByName(
          'allowed_ips',
          $this->t(
            'Invalid IP address or CIDR block: %value',
            ['%value' => $line]
          )
        );
      }
    }
  }

  /**
   * Validates a single IP address or CIDR notation entry.
   *
   * Accepts IPv4 addresses, IPv4 CIDR blocks, IPv6 addresses, and IPv6 CIDR
   * blocks. Uses filter_var for plain IP validation; parses the prefix host
   * for CIDR notation.
   *
   * @param string $value
   *   The IP or CIDR string to validate.
   *
   * @return bool
   *   TRUE if valid; FALSE otherwise.
   */
  private function isValidIpOrCidr(string $value): bool {
    if ($value === '') {
      return FALSE;
    }
    // Check plain IP address first.
    if (filter_var($value, FILTER_VALIDATE_IP) !== FALSE) {
      return TRUE;
    }
    // Check CIDR notation: split on '/' and validate host + prefix length.
    if (str_contains($value, '/')) {
      [$host, $prefix] = explode('/', $value, 2);
      if (filter_var($host, FILTER_VALIDATE_IP) === FALSE) {
        return FALSE;
      }
      if (!ctype_digit($prefix)) {
        return FALSE;
      }
      $prefixInt = (int) $prefix;
      // IPv4 prefix: 0-32; IPv6 prefix: 0-128.
      if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE) {
        return $prefixInt >= 0 && $prefixInt <= 32;
      }
      if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE) {
        return $prefixInt >= 0 && $prefixInt <= 128;
      }
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   *
   * Override the default copy to skip fields that need manual conversion.
   * The textarea and checkboxes fields return strings/arrays that must be
   * converted before assignment to the typed entity properties; they are
   * handled explicitly in save() instead.
   */
  protected function copyFormValuesToEntity(
    EntityInterface $entity,
    array $form,
    FormStateInterface $form_state,
  ): void {
    // These fields need custom conversion in save(); skip auto-copy.
    $manual = [
      'allowed_entity_types',
      'denied_entity_types',
      'redacted_fields',
      'roles',
      'status',
      'allow_read',
      'allow_write',
      'allow_delete',
      'allow_graphql_mutations',
      'rate_limit_requests',
      'rate_limit_window',
      'result_count_cap',
      'response_size_cap',
      'allowed_ips',
    ];
    assert($entity instanceof ConfigEntityBase);
    foreach ($form_state->getValues() as $key => $value) {
      if (!in_array($key, $manual, TRUE)) {
        $entity->set($key, $value);
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function save(array $form, FormStateInterface $form_state): int {
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile */
    $profile = $this->entity;
    $split = static fn (string $v): array => array_values(
      array_filter(array_map('trim', explode("\n", $v)))
    );

    $profile->setStatus((bool) $form_state->getValue('status'));
    $profile->set(
      'roles',
      array_values(array_filter($form_state->getValue('roles')))
    );
    foreach ([
      'allow_read',
      'allow_write',
      'allow_delete',
      'allow_graphql_mutations',
    ] as $key) {
      $profile->set($key, (bool) $form_state->getValue($key));
    }
    $profile->set(
      'allowed_entity_types',
      $split($form_state->getValue('allowed_entity_types'))
    );
    $profile->set(
      'denied_entity_types',
      $split($form_state->getValue('denied_entity_types'))
    );
    $profile->set(
      'redacted_fields',
      $split($form_state->getValue('redacted_fields'))
    );
    $profile->set('rate_limit_requests', (int) $form_state->getValue('rate_limit_requests'));
    $profile->set('rate_limit_window', (int) $form_state->getValue('rate_limit_window'));
    $profile->set('result_count_cap', (int) $form_state->getValue('result_count_cap'));
    $profile->set('response_size_cap', (int) $form_state->getValue('response_size_cap'));
    $profile->set(
      'allowed_ips',
      $split($form_state->getValue('allowed_ips'))
    );

    $status = $profile->save();
    $this->messenger()->addStatus(
      $this->t('Saved the %label profile.', ['%label' => $profile->label()])
    );
    $form_state->setRedirectUrl($profile->toUrl('collection'));
    return $status;
  }

}
