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

    $form['label'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Label'),
      '#default_value' => $profile->label(),
      '#required' => TRUE,
    ];
    $form['id'] = [
      '#type' => 'machine_name',
      '#default_value' => $profile->id(),
      '#machine_name' => [
        'exists' => '\Drupal\mcp_sentinel\Entity\McpPolicyProfile::load',
      ],
      '#disabled' => !$profile->isNew(),
    ];
    $form['status'] = [
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

    $form['roles'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Roles'),
      '#description' => $this->t(
        'Apply this profile to agents holding any of these roles. Leave empty for the default profile that applies to every governed agent without a more specific match.'
      ),
      '#options' => $role_options,
      '#default_value' => $profile->getRoles(),
    ];
    $form['weight'] = [
      '#type' => 'number',
      '#title' => $this->t('Weight'),
      '#description' => $this->t(
        'Higher weight wins when multiple profiles match an agent.'
      ),
      '#default_value' => $profile->getWeight(),
    ];

    $form['gates'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Allowed operations'),
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

    $lines = static fn (array $v): string => implode("\n", $v);
    $form['allowed_entity_types'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed entity types (empty = all)'),
      '#default_value' => $lines($profile->getAllowedEntityTypes()),
      '#rows' => 3,
    ];
    $form['denied_entity_types'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Denied entity types'),
      '#default_value' => $lines($profile->getDeniedEntityTypes()),
      '#rows' => 3,
    ];
    $form['redacted_fields'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Redacted fields'),
      '#default_value' => $lines($profile->getRedactedFields()),
      '#rows' => 3,
    ];

    $form['rate_limits'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Rate limits'),
      '#description' => $this->t('Throttle governed agent traffic per account. 0 = unlimited. Recommended starting values: 300 requests / 60 s window.'),
    ];
    $form['rate_limits']['rate_limit_requests'] = [
      '#type' => 'number',
      '#min' => 0,
      '#title' => $this->t('Max requests per window (0 = unlimited)'),
      '#default_value' => $profile->getRateLimitRequests(),
    ];
    $form['rate_limits']['rate_limit_window'] = [
      '#type' => 'number',
      '#min' => 1,
      '#title' => $this->t('Window (seconds)'),
      '#default_value' => $profile->getRateLimitWindow() ?: 60,
      '#states' => [
        'visible' => [
          ':input[name="rate_limit_requests"]' => ['!value' => '0'],
        ],
      ],
    ];

    $form['quotas'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Exfiltration guards'),
      // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
      '#description' => $this->t('Caps applied to governed reads before results leave the server. 0 = unlimited. Recommended starting values: 500 result items / 2 MB response size. Applies to Tool output (succeeded lists), GraphQL multi-value field results, and JSON:API page[limit] requests.'),
    ];
    $form['quotas']['result_count_cap'] = [
      '#type' => 'number',
      '#min' => 0,
      '#title' => $this->t('Max result items (0 = unlimited)'),
      // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
      '#description' => $this->t('Maximum items returned per Tool call, JSON:API page request, or GraphQL field result list. Recommended: 500.'),
      '#default_value' => $profile->getResultCountCap(),
    ];
    $form['quotas']['response_size_cap'] = [
      '#type' => 'number',
      '#min' => 0,
      '#title' => $this->t('Max response size in bytes (0 = unlimited)'),
      // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
      '#description' => $this->t('Maximum serialized response size in bytes for governed Tool calls. Responses exceeding this cap are denied. Recommended: 2097152 (2 MB).'),
      '#default_value' => $profile->getResponseSizeCap(),
    ];

    $form['ip_allowlist'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('IP allowlist'),
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
