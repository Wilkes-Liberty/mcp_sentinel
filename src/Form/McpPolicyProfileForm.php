<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\Core\Entity\EntityForm;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpRoleAssertions;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Add/edit form for an MCP policy profile.
 */
final class McpPolicyProfileForm extends EntityForm {

  /**
   * The role-assertion service.
   */
  protected McpRoleAssertions $roleAssertions;

  /**
   * The classification resolver (vocabulary for the ceiling selects).
   */
  protected McpClassificationResolver $classification;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = parent::create($container);
    $instance->roleAssertions = $container->get('mcp_sentinel.role_assertions');
    $instance->classification = $container->get('mcp_sentinel.classification');
    return $instance;
  }

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
    // The AJAX attributes shared by all gate checkboxes: on change, refresh the
    // policy-preview wrapper in the Identity tab.
    $preview_ajax = [
      'callback' => '::previewAjax',
      'wrapper' => 'mcp-policy-preview-wrapper',
      'event' => 'change',
    ];
    foreach ([
      'allow_read' => [
        $this->t('Allow read'),
        $this->t('Permit governed read, list, and get operations. Sentinel never grants what core access denies — turning a gate off only adds a restriction on top of core access.'),
      ],
      'allow_write' => [
        $this->t('Allow write (create, update)'),
        $this->t('Permit create and update operations. When off, every governed write is blocked even when the Drupal role would allow it.'),
      ],
      'allow_delete' => [
        $this->t('Allow delete'),
        $this->t('Permit delete operations. Off by default; prefer the per-entity-type overrides below to opening delete for every type at once.'),
      ],
      'allow_graphql_mutations' => [
        $this->t('Allow GraphQL mutations'),
        $this->t('Permit GraphQL mutation operations. Read queries are unaffected; leave off unless the agent must mutate through GraphQL.'),
      ],
    ] as $key => [$label, $gate_description]) {
      $form['gates'][$key] = [
        '#type' => 'checkbox',
        '#title' => $label,
        '#description' => $gate_description,
        '#default_value' => $profile->get($key),
        '#ajax' => $preview_ajax,
      ];
    }

    // Per-entity-type delete overrides. Listing an entity type here grants
    // delete for that type only, overriding the global "Allow delete" gate
    // above. The global flag remains the default for every unlisted type.
    $delete_override_types = [];
    foreach ($profile->getEntityRules() as $type => $rule) {
      if (!empty($rule['allow_delete'])) {
        $delete_override_types[] = $type;
      }
    }
    $form['gates']['entity_rules_delete'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Per-entity-type delete overrides'),
      '#description' => $this->t('One entity type machine name per line (e.g. taxonomy_term). Listed types are permitted to be deleted even when the global "Allow delete" gate above is off — the global flag stays the default for every other type. The Drupal role permission (e.g. "delete terms in <vocabulary>") still applies as an independent second gate.'),
      '#default_value' => implode("\n", $delete_override_types),
      '#rows' => 3,
    ];

    // --- Configuration governance tab ----------------------------------------
    $form['config_governance'] = [
      '#type' => 'details',
      '#title' => $this->t('Configuration governance'),
      '#group' => 'tabs',
    ];
    $form['config_governance']['allow_config_read'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow configuration read'),
      '#description' => $this->t('Permit governed config get/list operations. Off by default.'),
      '#default_value' => $profile->get('allow_config_read'),
    ];
    $form['config_governance']['allow_config_write'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow configuration write'),
      '#description' => $this->t('Permit governed config set operations. Off by default; reserve for developer-tier profiles.'),
      '#default_value' => $profile->get('allow_config_write'),
    ];
    $form['config_governance']['denied_config_types'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Denied configuration name prefixes'),
      '#description' => $this->t('One config name or prefix per line (e.g. system., field.field.). Matching config is denied for read and write regardless of the allow flags above.'),
      '#default_value' => implode("\n", $profile->getDeniedConfigTypes()),
      '#rows' => 3,
    ];
    $form['config_governance']['deny_publish'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Deny publishing (force draft / unpublished)'),
      '#description' => $this->t('When on (recommended), agent-authored content cannot be published: moderated transitions to a published state are denied and unmoderated publishable entities are saved unpublished. A human publisher publishes.'),
      '#default_value' => $profile->get('deny_publish'),
    ];
    $form['config_governance']['max_moderation_state'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Maximum moderation state (empty = unrestricted)'),
      '#description' => $this->t('Optional ceiling state ID (e.g. draft, needs_review). Transitions to a higher-weight workflow state are denied. Leave empty for no ceiling.'),
      '#default_value' => $profile->getMaxModerationState(),
    ];
    $form['config_governance']['deny_external_redirects'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Deny off-domain redirects (open-redirect guard)'),
      '#description' => $this->t('When on (recommended), a governed agent cannot create or update a redirect whose destination points to an external host outside the allowlist below. Internal:, entity:, base:, and relative targets are always permitted. Has no effect unless the redirect module is installed.'),
      '#default_value' => $profile->get('deny_external_redirects'),
    ];
    $form['config_governance']['allowed_redirect_hosts'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed external redirect hosts'),
      '#description' => $this->t("One hostname per line (e.g. docs.example.com). External redirect targets on these hosts are permitted. Leave empty to allow only the site's own host(s), derived from the request host and trusted_host_patterns."),
      '#default_value' => implode("\n", $profile->getAllowedRedirectHosts()),
      '#rows' => 3,
      '#states' => [
        'visible' => [
          ':input[name="deny_external_redirects"]' => ['checked' => TRUE],
        ],
      ],
    ];

    // --- Role assertions tab -------------------------------------------------
    $form['role_assertions'] = [
      '#type' => 'details',
      '#title' => $this->t('Role assertions'),
      '#group' => 'tabs',
      '#description' => $this->t('A policy profile constrains what the agent may do <em>through the MCP channel</em>. These assertions cover what its Drupal role can do <em>outside</em> it — where no policy, redaction or audit applies. Violations are reported on the governance dashboard and the status report, and fail <code>drush mcp-sentinel:role-audit</code>.'),
    ];
    $form['role_assertions']['forbidden_role_permissions'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Permissions a governed role must not hold'),
      '#description' => $this->t('One permission machine name per line. Add the escape hatches your own contrib modules define — anything that lets its holder read or write outside the agent channel.'),
      '#default_value' => implode("\n", $profile->getForbiddenRolePermissions()),
      '#rows' => 6,
    ];
    $form['role_assertions']['acknowledged_role_permissions'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Acknowledged deliberate grants'),
      '#description' => $this->t("One entry per line. Unscoped <code>role_id:permission</code> applies on every environment (e.g. <code>mcp_content_editor:bypass file gate</code>). Scoped <code>role_id:permission@environment</code> applies only when <code>\$settings['mcp_sentinel.environment']</code> in settings.php matches (e.g. <code>mcp_config_editor:administer site configuration@dev</code>). With no environment declared, a scoped entry does not apply — the violation is reported. The environment name comes from settings.php, never from config, so a grant allowed on one environment cannot travel with a config export. Use this to record a considered exception rather than deleting the rule that caught it."),
      '#default_value' => implode("\n", $profile->getAcknowledgedRolePermissions()),
      '#rows' => 4,
    ];

    $form['config_governance']['allow_raw_sql'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow raw SQL (governed Drush command)'),
      '#description' => $this->t('Off by default. When on, this profile may run single SELECT statements through <code>drush mcp-sentinel:sql-query</code>, which refuses any statement touching a denied entity type or a redacted field and records every attempt in the audit chain. Raw SQL is a narrower boundary than an entity read even when governed — leave this off unless a reviewed workflow needs it.'),
      '#default_value' => $profile->get('allow_raw_sql'),
    ];

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
      '#title' => $this->t('Max requests per window (0 = site default)'),
      '#description' => $this->t('Throttle governed agent traffic per account. 0 uses the finite site default (unlimited only when the non-production override is active). Recommended: 300.'),
      '#default_value' => $profile->getRateLimitRequests(),
      '#ajax' => $preview_ajax,
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
      '#ajax' => $preview_ajax,
    ];
    $form['limits']['result_count_cap'] = [
      '#type' => 'number',
      '#min' => 0,
      '#title' => $this->t('Max result items (0 = site default)'),
      // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
      '#description' => $this->t('Maximum items returned per Tool call, JSON:API page request, or GraphQL field result list. Recommended: 500.'),
      '#default_value' => $profile->getResultCountCap(),
      '#ajax' => $preview_ajax,
    ];
    $form['limits']['response_size_cap'] = [
      '#type' => 'number',
      '#min' => 0,
      '#title' => $this->t('Max response size in bytes (0 = site default)'),
      // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
      '#description' => $this->t('Maximum serialized response size in bytes for governed Tool calls. Responses exceeding this cap are denied. Recommended: 2097152 (2 MB).'),
      '#default_value' => $profile->getResponseSizeCap(),
      '#ajax' => $preview_ajax,
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

    // --- Egress ceilings tab (d.o #3616540 part 2) ---------------------------
    // The one #tree group on this form: the values must land as one map keyed
    // by surface, and save() writes it explicitly.
    $form['egress'] = [
      '#type' => 'details',
      '#title' => $this->t('Egress ceilings'),
      '#description' => $this->t('The highest classification label this profile may receive on each governed surface. Data labelled above a ceiling is refused (or redacted, per field) on that surface with the code <code>classification_egress_denied</code>. A surface without a ceiling receives everything its other gates allow; hard entity-type denies and redacted fields always win. Labels come from the classification vocabulary in the module settings.'),
      '#group' => 'tabs',
    ];
    $form['egress']['egress_ceilings'] = [
      '#type' => 'container',
      '#tree' => TRUE,
    ];
    $options = ['' => $this->t('- No ceiling -')];
    foreach ($this->classification->labels() as $label) {
      $options[$label] = $label;
    }
    $ceilings = $profile->getEgressCeilings();
    $surfaces = [
      McpGovernedSurface::Tool->value => $this->t('Tool (governed MCP tools)'),
      McpGovernedSurface::Context->value => $this->t('Context endpoint (site schema)'),
      McpGovernedSurface::JsonApi->value => $this->t('JSON:API'),
      McpGovernedSurface::Graphql->value => $this->t('GraphQL'),
      McpGovernedSurface::Drush->value => $this->t('Governed drush SQL'),
    ];
    foreach ($surfaces as $surface => $title) {
      $current = $ceilings[$surface] ?? '';
      if ($current !== '' && !isset($options[$current])) {
        // A ceiling naming a label outside the vocabulary is enforced as the
        // lowest label; keep it visible so the operator can see and fix it.
        $options[$current] = $this->t('@label (not in vocabulary)', ['@label' => $current]);
      }
      $form['egress']['egress_ceilings'][$surface] = [
        '#type' => 'select',
        '#title' => $title,
        '#options' => $options,
        '#default_value' => $current,
      ];
    }

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
      : $this->t('site default');
    $result_str = ($result_cap > 0) ? (string) $result_cap : (string) $this->t('site default');
    $resp_str = ($resp_cap > 0) ? (string) $resp_cap . ' B' : (string) $this->t('site default');
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
   * AJAX callback: refresh the policy-preview element.
   *
   * Called when a gate checkbox or a cap/rate-limit number field changes.
   * Returns the preview render sub-array; Drupal replaces the wrapper.
   *
   * @param array $form
   *   The form render array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current form state.
   *
   * @return array
   *   The preview render array (includes its own prefix/suffix wrapper).
   */
  public function previewAjax(array &$form, FormStateInterface $form_state): array {
    return $form['identity']['preview'];
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    // Refuse to govern an admin role at all, at the point the choice is made.
    //
    // An is_admin role holds every permission implicitly, including any a
    // module installed tomorrow will define, so no profile can constrain it and
    // no forbidden-permission list can enumerate it. Blocking it here — rather
    // than only reporting it afterwards — is the difference between a control
    // and a complaint.
    //
    // Note the runtime does NOT drop such a role from governance if one is
    // already configured (see McpRoleAssertions): un-governing it would leave
    // the agent's traffic entirely ungoverned, which is worse than governing it
    // imperfectly and shouting about it on the status report.
    foreach (array_filter((array) $form_state->getValue('roles')) as $roleId) {
      if ($this->roleAssertions->isAdminRole((string) $roleId)) {
        $form_state->setErrorByName('roles', $this->t(
          "Role %role is an administrator role, so it holds every permission on the site and cannot be constrained by a policy profile. Govern a purpose-built role instead.",
          ['%role' => $roleId],
        ));
      }
    }

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
      'allow_config_read',
      'allow_config_write',
      'denied_config_types',
      'deny_publish',
      'max_moderation_state',
      'deny_external_redirects',
      'allowed_redirect_hosts',
      'forbidden_role_permissions',
      'acknowledged_role_permissions',
      'allow_raw_sql',
      'entity_rules_delete',
      'egress_ceilings',
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
    foreach ([
      'allow_config_read',
      'allow_config_write',
      'deny_publish',
      'deny_external_redirects',
      'allow_raw_sql',
    ] as $key) {
      $profile->set($key, (bool) $form_state->getValue($key));
    }
    $profile->set(
      'denied_config_types',
      $split($form_state->getValue('denied_config_types'))
    );
    $profile->set(
      'max_moderation_state',
      trim((string) $form_state->getValue('max_moderation_state'))
    );
    $profile->set(
      'allowed_redirect_hosts',
      $split($form_state->getValue('allowed_redirect_hosts'))
    );
    // Egress ceilings: an empty select is an absent key (no ceiling), never
    // an empty-string ceiling.
    $ceilings = [];
    foreach ((array) ($form_state->getValue('egress_ceilings') ?? []) as $surface => $label) {
      $label = trim((string) $label);
      if ($label !== '' && McpGovernedSurface::tryFrom((string) $surface) !== NULL) {
        $ceilings[(string) $surface] = $label;
      }
    }
    $profile->set('egress_ceilings', $ceilings);
    $profile->set(
      'forbidden_role_permissions',
      $split($form_state->getValue('forbidden_role_permissions'))
    );
    $profile->set(
      'acknowledged_role_permissions',
      $split($form_state->getValue('acknowledged_role_permissions'))
    );

    // Rebuild the per-entity-type rule map from the delete-overrides textarea,
    // preserving any non-delete keys (e.g. allow_write overrides set via config
    // YAML) so the form does not clobber them.
    $rules = [];
    foreach (($profile->get('entity_rules') ?: []) as $type => $rule) {
      unset($rule['allow_delete']);
      if ($rule !== []) {
        $rules[$type] = $rule;
      }
    }
    foreach ($split($form_state->getValue('entity_rules_delete')) as $type) {
      $rules[$type]['allow_delete'] = TRUE;
    }
    ksort($rules);
    $profile->set('entity_rules', $rules);

    $status = $profile->save();
    $this->messenger()->addStatus(
      $this->t('Saved the %label profile.', ['%label' => $profile->label()])
    );
    $form_state->setRedirectUrl($profile->toUrl('collection'));
    return $status;
  }

}
