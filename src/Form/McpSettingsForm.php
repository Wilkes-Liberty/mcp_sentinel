<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\mcp_sentinel\Service\McpDlp;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * MCP Sentinel administration settings form.
 *
 * Covers the global master switch, governed roles, audit logging, and webhook
 * settings. Per-agent access policy (allowed operations, entity types, field
 * redaction) is managed through policy profiles.
 */
class McpSettingsForm extends ConfigFormBase {

  use McpListEditorTrait;

  /**
   * The entity type manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * The encryption profile manager.
   */
  protected EncryptionProfileManagerInterface $encryptionProfileManager;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = parent::create($container);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->encryptionProfileManager = $container->get('encrypt.encryption_profile.manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['mcp_sentinel.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'mcp_sentinel_settings';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('mcp_sentinel.settings');

    $form['tabs'] = ['#type' => 'vertical_tabs', '#default_tab' => 'edit-status'];
    $form['#attached']['library'][] = 'mcp_sentinel/admin';

    $form['status'] = [
      '#type' => 'details',
      '#title' => $this->t('MCP Access'),
      '#group' => 'tabs',
      '#open' => TRUE,
    ];
    $form['status']['enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable MCP API access'),
      '#description' => $this->t('Master switch. When disabled, all MCP requests receive 403 regardless of credentials or profile.'),
      '#default_value' => $config->get('enabled') ?? TRUE,
    ];
    /** @var \Drupal\user\RoleInterface[] $roles */
    $roles = $this->entityTypeManager->getStorage('user_role')->loadMultiple();
    $role_options = [];
    foreach ($roles as $rid => $role) {
      $role_options[$rid] = (string) $role->label();
    }
    unset($role_options['anonymous'], $role_options['authenticated']);
    $form['status']['governed_roles'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Governed roles'),
      '#description' => $this->t('Agents holding any of these roles are governed by MCP Sentinel. Per-agent policy is configured under <a href=":url">policy profiles</a>.', [
        ':url' => '/admin/config/services/mcp-sentinel/profiles',
      ]),
      '#options' => $role_options,
      '#default_value' => $config->get('governed_roles') ?? ['mcp_api'],
    ];

    $lines = static fn (array $v): string => implode("\n", $v);
    $form['oauth'] = [
      '#type' => 'details',
      '#title' => $this->t('OAuth agent channel'),
      '#description' => $this->t('Governance triggers when a request is authenticated via the OAuth agent channel (a designated consumer or an agent scope on the access token). See the connector runbook for setup.'),
      '#group' => 'tabs',
    ];
    $form['oauth']['agent_scopes'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Agent scopes'),
      '#description' => $this->t('One OAuth scope per line. A token carrying any of these scopes is on the agent channel.'),
      '#default_value' => $lines($config->get('agent_scopes') ?? ['mcp_read', 'mcp_write']),
      '#rows' => 3,
    ];
    $form['oauth']['agent_oauth_clients'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Agent OAuth client IDs (optional)'),
      '#description' => $this->t('One consumer client_id per line. When set, only tokens from these consumers are on the agent channel; leave empty to match purely on scope.'),
      '#default_value' => $lines($config->get('agent_oauth_clients') ?? []),
      '#rows' => 3,
    ];
    $form['oauth']['governed_role_fallback'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Govern by role without an OAuth token (local dev only)'),
      '#description' => $this->t('When enabled, a request from a user holding a governed role is governed even without an OAuth agent token. Leave OFF in production so the admin UI stays ungoverned.'),
      '#default_value' => $config->get('governed_role_fallback') ?? FALSE,
    ];

    $form['audit'] = [
      '#type' => 'details',
      '#title' => $this->t('Audit Logging'),
      '#group' => 'tabs',
    ];
    $form['audit']['audit_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable audit logging'),
      '#default_value' => $config->get('audit_enabled') ?? TRUE,
    ];
    $form['audit']['audit_log_reads'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Log read operations (high volume)'),
      '#default_value' => $config->get('audit_log_reads') ?? FALSE,
      '#states'        => ['visible' => ['[name="audit_enabled"]' => ['checked' => TRUE]]],
    ];
    $form['audit']['audit_retention_days'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Retention (days, 0 = forever)'),
      '#default_value' => $config->get('audit_retention_days') ?? 90,
      '#min' => 0,
      '#max' => 3650,
      '#states'        => ['visible' => ['[name="audit_enabled"]' => ['checked' => TRUE]]],
    ];
    $form['audit']['audit_hash_key'] = [
      '#type'          => 'key_select',
      '#title'         => $this->t('Audit hash signing key (HMAC-SHA256)'),
      '#description'   => $this->t('Select a <a href=":url">Key</a> to sign the audit hash chain with HMAC-SHA256 instead of plain SHA-256. Recommended: use a File or Environment key provider so the secret never appears in exported configuration.', [
        ':url' => '/admin/config/system/keys',
      ]),
      '#default_value' => $config->get('audit_hash_key') ?? '',
      '#empty_option'  => $this->t('- None (plain SHA-256) -'),
      '#states'        => ['visible' => ['[name="audit_enabled"]' => ['checked' => TRUE]]],
    ];
    $form['audit']['siem_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable SIEM streaming'),
      '#description'   => $this->t('When enabled, each audit write is also emitted to the <code>mcp_sentinel_audit</code> logger channel as a structured JSON record. Route this channel to syslog or Monolog to stream events to a SIEM without DB polling.'),
      '#default_value' => $config->get('siem_enabled') ?? FALSE,
      '#states'        => ['visible' => ['[name="audit_enabled"]' => ['checked' => TRUE]]],
    ];

    $profiles = $this->encryptionProfileManager->getAllEncryptionProfiles();
    $profile_options = ['' => $this->t('- None (plaintext) -')];
    foreach ($profiles as $profile_id => $profile) {
      $profile_options[$profile_id] = (string) $profile->label();
    }
    $form['audit']['audit_encryption_profile'] = [
      '#type'          => 'select',
      '#title'         => $this->t('Audit metadata encryption profile'),
      '#description'   => $this->t('Select an <a href=":url">Encryption Profile</a> to encrypt audit metadata at rest. When set, the metadata column is encrypted on write and decrypted on read. Pre-existing plaintext rows remain readable (decryption failure gracefully falls back to JSON decode). Changing the profile later prevents decryption (and tamper-verification) of rows already encrypted under the previous profile — export or re-encrypt existing audit rows before rotating.', [
        ':url' => '/admin/config/system/encryption/profiles',
      ]),
      '#options'       => $profile_options,
      '#default_value' => $config->get('audit_encryption_profile') ?? '',
      '#states'        => ['visible' => ['[name="audit_enabled"]' => ['checked' => TRUE]]],
    ];

    $form['dlp'] = [
      '#type' => 'details',
      '#title' => $this->t('Data Loss Prevention (DLP)'),
      '#description' => $this->t('Value-pattern scanning for PII in governed field output. Off by default — opt in by enabling below.'),
      '#group' => 'tabs',
    ];
    $form['dlp']['dlp_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable DLP value-pattern scanning'),
      '#description'   => $this->t('When enabled, outbound governed field values are scanned against the configured patterns and masked before delivery. V1 scope: GraphQL field output and audit change-diff capture. JSON:API/REST per-value scanning is deferred.'),
      '#default_value' => $config->get('dlp_enabled') ?? FALSE,
    ];
    $form['dlp']['dlp_mask_mode'] = [
      '#type'          => 'select',
      '#title'         => $this->t('Mask mode'),
      '#description'   => $this->t('<strong>Redact:</strong> replace the full PII match with <code>[REDACTED]</code>. <strong>Partial:</strong> keep the last 4 characters and mask the rest with <code>*</code> (e.g. <code>************4567</code> for a credit-card number).'),
      '#options'       => [
        'redact'  => $this->t('Redact (replace with [REDACTED])'),
        'partial' => $this->t('Partial (keep last 4 chars, mask the rest with *)'),
      ],
      '#default_value' => $config->get('dlp_mask_mode') ?? 'redact',
      '#states'        => ['visible' => ['[name="dlp_enabled"]' => ['checked' => TRUE]]],
    ];

    // Build the DLP patterns multi-row editor from stored config.
    $stored_patterns = array_values(array_filter(
      (array) ($config->get('dlp_patterns') ?? []),
      'is_array',
    ));
    $dlp_count = $this->rowCount($form_state, 'dlp_patterns_rows', count($stored_patterns));
    $form['dlp']['dlp_patterns_help'] = [
      '#type' => 'item',
      '#title' => $this->t('Custom DLP patterns'),
      '#description' => $this->t('Each row is a pattern: <code>label</code>, <code>regex</code> and an optional <code>mask</code> (defaults to <code>*</code>). The <code>regex</code> is a PCRE body WITHOUT delimiters — wrapped in <code>#…#i</code> automatically (example: <code>EMP-\d{6}</code>). Leave all rows blank to fall back to the four built-in defaults (email, US phone, SSN, credit card). Invalid regular expressions are rejected.'),
      '#states' => ['visible' => ['[name="dlp_enabled"]' => ['checked' => TRUE]]],
    ];
    $form['dlp']['dlp_patterns_rows'] = [
      '#type' => 'container',
      '#tree' => TRUE,
      '#prefix' => '<div id="mcp-dlp-rows-wrapper">',
      '#suffix' => '</div>',
      '#states' => ['visible' => ['[name="dlp_enabled"]' => ['checked' => TRUE]]],
    ];
    for ($i = 0; $i < $dlp_count; $i++) {
      $row = $stored_patterns[$i] ?? [];
      $form['dlp']['dlp_patterns_rows'][$i] = [
        '#type' => 'fieldset',
        '#title' => $this->t('Pattern @n', ['@n' => $i + 1]),
        '#attributes' => ['class' => ['mcp-sentinel-row']],
      ];
      $form['dlp']['dlp_patterns_rows'][$i]['label'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Label'),
        '#default_value' => (string) ($row['label'] ?? ''),
        '#size' => 24,
        '#maxlength' => 128,
      ];
      $form['dlp']['dlp_patterns_rows'][$i]['regex'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Pattern (regex)'),
        '#default_value' => (string) ($row['regex'] ?? ''),
        '#size' => 40,
      ];
      $form['dlp']['dlp_patterns_rows'][$i]['mask'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Mask'),
        '#default_value' => (string) ($row['mask'] ?? ''),
        '#size' => 6,
        '#maxlength' => 16,
      ];
      $form['dlp']['dlp_patterns_rows'][$i]['remove'] = [
        '#type' => 'submit',
        '#name' => 'dlp_remove_' . $i,
        '#value' => $this->t('Remove pattern @n', ['@n' => $i + 1]),
        '#submit' => ['::dlpRemoveRow'],
        '#limit_validation_errors' => [],
        '#mcp_editor_parents' => ['dlp', 'dlp_patterns_rows'],
        '#mcp_editor_input' => ['dlp_patterns_rows'],
        '#mcp_editor_row' => $i,
        '#ajax' => [
          'callback' => '::listEditorAjax',
          'wrapper' => 'mcp-dlp-rows-wrapper',
        ],
      ];
    }
    $form['dlp']['dlp_patterns_rows']['add'] = [
      '#type' => 'submit',
      '#name' => 'dlp_add',
      '#value' => $this->t('Add pattern'),
      '#submit' => ['::dlpAddRow'],
      '#limit_validation_errors' => [],
      '#mcp_editor_parents' => ['dlp', 'dlp_patterns_rows'],
      '#ajax' => [
        'callback' => '::listEditorAjax',
        'wrapper' => 'mcp-dlp-rows-wrapper',
      ],
    ];

    // -----------------------------------------------------------------------
    // Anomaly detection tab.
    // -----------------------------------------------------------------------
    $form['anomaly'] = [
      '#type' => 'details',
      '#title' => $this->t('Anomaly detection'),
      '#description' => $this->t('Evaluates thresholds over the audit log on cron. All rules ship disabled; enable and tune per-site to avoid false positives during content imports.'),
      '#group' => 'tabs',
    ];
    $form['anomaly']['anomaly_enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable anomaly detection'),
      '#default_value' => $config->get('anomaly_enabled') ?? FALSE,
    ];
    $form['anomaly']['anomaly_alert_log'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Log alerts to MCP Sentinel logger channel'),
      '#default_value' => $config->get('anomaly_alert_log') ?? TRUE,
      '#states' => ['visible' => ['[name="anomaly_enabled"]' => ['checked' => TRUE]]],
    ];
    $form['anomaly']['anomaly_alert_email'] = [
      '#type' => 'email',
      '#title' => $this->t('Alert email address (empty = disabled)'),
      '#default_value' => $config->get('anomaly_alert_email') ?? '',
      '#description' => $this->t('When non-empty, an email is sent to this address for each fired rule. Requires a working mail setup.'),
      '#states' => ['visible' => ['[name="anomaly_enabled"]' => ['checked' => TRUE]]],
    ];
    $form['anomaly']['anomaly_alert_webhook'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Send alerts via webhook queue (requires configured endpoints)'),
      '#description' => $this->t('Enqueues an <code>mcp.anomaly.alert</code> event for each fired rule. Endpoints whose event filter includes <code>mcp.anomaly.alert</code> (or an empty filter) receive it.'),
      '#default_value' => $config->get('anomaly_alert_webhook') ?? FALSE,
      '#states' => ['visible' => ['[name="anomaly_enabled"]' => ['checked' => TRUE]]],
    ];

    // Build the anomaly rules multi-row editor from stored config. At least two
    // rows are shown so an operator can add several rules without round trips.
    $stored_rules = array_values(array_filter(
      (array) ($config->get('anomaly_rules') ?? []),
      'is_array',
    ));
    $anomaly_seed = max(count($stored_rules), 1);
    $anomaly_count = $this->rowCount($form_state, 'anomaly_rules_rows', $anomaly_seed);
    $form['anomaly']['anomaly_rules_help'] = [
      '#type' => 'item',
      '#title' => $this->t('Rules'),
      '#description' => $this->t('Each row is one rule. The <code>operation_pattern</code> is an <strong>exact match by default</strong> — <code>entity_delete</code> matches only <code>entity_delete</code>. Append <code>*</code> for a prefix match — <code>entity*</code> matches both <code>entity_save</code> and <code>entity_delete</code>. All rules ship disabled; tick <em>Enabled</em> per rule.'),
      '#states' => ['visible' => ['[name="anomaly_enabled"]' => ['checked' => TRUE]]],
    ];
    $form['anomaly']['anomaly_rules_rows'] = [
      '#type' => 'container',
      '#tree' => TRUE,
      '#prefix' => '<div id="mcp-anomaly-rows-wrapper">',
      '#suffix' => '</div>',
      '#states' => ['visible' => ['[name="anomaly_enabled"]' => ['checked' => TRUE]]],
    ];
    for ($i = 0; $i < $anomaly_count; $i++) {
      $rule = $stored_rules[$i] ?? [];
      $form['anomaly']['anomaly_rules_rows'][$i] = [
        '#type' => 'fieldset',
        '#title' => $this->t('Rule @n', ['@n' => $i + 1]),
        '#attributes' => ['class' => ['mcp-sentinel-row']],
      ];
      $form['anomaly']['anomaly_rules_rows'][$i]['id'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Machine ID'),
        '#default_value' => (string) ($rule['id'] ?? ''),
        '#size' => 24,
        '#maxlength' => 64,
      ];
      $form['anomaly']['anomaly_rules_rows'][$i]['label'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Label'),
        '#default_value' => (string) ($rule['label'] ?? ''),
        '#size' => 24,
        '#maxlength' => 128,
      ];
      $form['anomaly']['anomaly_rules_rows'][$i]['operation_pattern'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Operation pattern'),
        '#default_value' => (string) ($rule['operation_pattern'] ?? ''),
        '#size' => 24,
      ];
      $form['anomaly']['anomaly_rules_rows'][$i]['window_seconds'] = [
        '#type' => 'number',
        '#title' => $this->t('Window (s)'),
        '#default_value' => (int) ($rule['window_seconds'] ?? 300),
        '#min' => 1,
        '#size' => 8,
      ];
      $form['anomaly']['anomaly_rules_rows'][$i]['threshold'] = [
        '#type' => 'number',
        '#title' => $this->t('Threshold'),
        '#default_value' => (int) ($rule['threshold'] ?? 10),
        '#min' => 1,
        '#size' => 8,
      ];
      $form['anomaly']['anomaly_rules_rows'][$i]['debounce_seconds'] = [
        '#type' => 'number',
        '#title' => $this->t('Debounce (s)'),
        '#default_value' => (int) ($rule['debounce_seconds'] ?? 3600),
        '#min' => 0,
        '#size' => 8,
      ];
      $form['anomaly']['anomaly_rules_rows'][$i]['enabled'] = [
        '#type' => 'checkbox',
        '#title' => $this->t('Enabled'),
        '#default_value' => !empty($rule['enabled']),
      ];
      $form['anomaly']['anomaly_rules_rows'][$i]['remove'] = [
        '#type' => 'submit',
        '#name' => 'anomaly_remove_' . $i,
        '#value' => $this->t('Remove rule @n', ['@n' => $i + 1]),
        '#submit' => ['::anomalyRemoveRow'],
        '#limit_validation_errors' => [],
        '#mcp_editor_parents' => ['anomaly', 'anomaly_rules_rows'],
        '#mcp_editor_input' => ['anomaly_rules_rows'],
        '#mcp_editor_row' => $i,
        '#ajax' => [
          'callback' => '::listEditorAjax',
          'wrapper' => 'mcp-anomaly-rows-wrapper',
        ],
      ];
    }
    $form['anomaly']['anomaly_rules_rows']['add'] = [
      '#type' => 'submit',
      '#name' => 'anomaly_add',
      '#value' => $this->t('Add rule'),
      '#submit' => ['::anomalyAddRow'],
      '#limit_validation_errors' => [],
      '#mcp_editor_parents' => ['anomaly', 'anomaly_rules_rows'],
      '#ajax' => [
        'callback' => '::listEditorAjax',
        'wrapper' => 'mcp-anomaly-rows-wrapper',
      ],
    ];

    $form['webhooks'] = [
      '#type' => 'details',
      '#title' => $this->t('Reliable webhooks'),
      '#description' => $this->t('Configure one or more HTTPS endpoints. Each matching event records a delivery row and is queued for delivery with HMAC-SHA256 signing, retry/backoff (5 attempts over 30 s–8 h) and an SSRF guard. Review the <a href=":url">webhook delivery log</a>.', [
        ':url' => '/admin/reports/mcp-sentinel/webhooks',
      ]),
      '#tree' => TRUE,
      '#group' => 'tabs',
    ];
    $form['webhooks']['webhook_delivery_retention_days'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Delivery log retention (days, 0 = forever)'),
      '#default_value' => $config->get('webhook_delivery_retention_days') ?? 30,
      '#min'           => 0,
      '#max'           => 3650,
    ];
    $form['webhooks']['allow_internal_webhook_urls'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Allow internal/private endpoint URLs — global (deprecated)'),
      '#description'   => $this->t('Deprecated. Use the per-endpoint <em>Allow internal/VPN destination</em> checkbox instead, which scopes the opt-out to a single endpoint. This global flag is no longer read by the worker.'),
      '#default_value' => $config->get('allow_internal_webhook_urls') ?? FALSE,
    ];

    // Key options for the per-endpoint signing-secret select.
    /** @var \Drupal\key\KeyInterface[] $keys */
    $keys = $this->entityTypeManager->getStorage('key')->loadMultiple();
    $key_options = ['' => $this->t('- None -')];
    foreach ($keys as $key_id => $key) {
      $key_options[$key_id] = (string) $key->label();
    }

    // Render existing endpoints as dynamic add/remove rows. The row count is
    // tracked in form-state storage and seeds from the stored endpoint count
    // (plus a blank trailing slot) on first build. Field names are kept stable
    // (webhooks[endpoints][N][...]) so validation/submit are unchanged.
    $endpoints = array_values((array) ($config->get('webhook_endpoints') ?? []));
    // Seed at least one row so an empty editor still shows a blank slot (plus
    // the trailing slot the trait always adds).
    $slots = $this->rowCount($form_state, 'webhook_endpoints_rows', max(count($endpoints), 1));
    $form['webhooks']['endpoints'] = [
      '#type' => 'container',
      '#tree' => TRUE,
      '#prefix' => '<div id="mcp-webhook-endpoints-wrapper">',
      '#suffix' => '</div>',
    ];
    for ($i = 0; $i < $slots; $i++) {
      $ep = $endpoints[$i] ?? [];
      $form['webhooks']['endpoints'][$i] = [
        '#type' => 'details',
        '#title' => $this->t('Endpoint @n', ['@n' => $i + 1]),
        '#open' => $i < count($endpoints),
      ];
      $form['webhooks']['endpoints'][$i]['id'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Machine ID'),
        '#default_value' => (string) ($ep['id'] ?? ''),
        '#size' => 32,
        '#maxlength' => 64,
        '#description' => $this->t('Lowercase letters, numbers and underscores. Leave the whole endpoint blank to skip it.'),
      ];
      $form['webhooks']['endpoints'][$i]['label'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Label'),
        '#default_value' => (string) ($ep['label'] ?? ''),
        '#size' => 40,
        '#maxlength' => 128,
      ];
      $form['webhooks']['endpoints'][$i]['url'] = [
        '#type' => 'url',
        '#title' => $this->t('Endpoint URL (HTTPS required)'),
        '#default_value' => (string) ($ep['url'] ?? ''),
      ];
      $form['webhooks']['endpoints'][$i]['secret_key'] = [
        '#type' => 'select',
        '#title' => $this->t('Signing secret (Key)'),
        '#options' => $key_options,
        '#default_value' => (string) ($ep['secret_key'] ?? ''),
      ];
      $form['webhooks']['endpoints'][$i]['events'] = [
        '#type' => 'textarea',
        '#title' => $this->t('Event filter (one per line; empty = all events)'),
        '#default_value' => implode("\n", (array) ($ep['events'] ?? [])),
        '#rows' => 3,
      ];
      $form['webhooks']['endpoints'][$i]['enabled'] = [
        '#type' => 'checkbox',
        '#title' => $this->t('Enabled'),
        '#default_value' => !empty($ep['enabled']),
      ];
      $form['webhooks']['endpoints'][$i]['allow_internal'] = [
        '#type' => 'checkbox',
        '#title' => $this->t('Allow internal/VPN destination (disables SSRF DNS guard for this endpoint only)'),
        '#description' => $this->t('Only enable for a receiver that genuinely lives on an internal network or VPN. HTTPS is still required regardless of this setting.'),
        '#default_value' => !empty($ep['allow_internal']),
      ];
      $form['webhooks']['endpoints'][$i]['remove'] = [
        '#type' => 'submit',
        '#name' => 'webhook_remove_' . $i,
        '#value' => $this->t('Remove endpoint @n', ['@n' => $i + 1]),
        '#submit' => ['::webhookRemoveRow'],
        '#limit_validation_errors' => [],
        '#mcp_editor_parents' => ['webhooks', 'endpoints'],
        '#mcp_editor_input' => ['webhooks', 'endpoints'],
        '#mcp_editor_row' => $i,
        '#ajax' => [
          'callback' => '::listEditorAjax',
          'wrapper' => 'mcp-webhook-endpoints-wrapper',
        ],
      ];
    }
    $form['webhooks']['endpoints']['add'] = [
      '#type' => 'submit',
      '#name' => 'webhook_add',
      '#value' => $this->t('Add endpoint'),
      '#submit' => ['::webhookAddRow'],
      '#limit_validation_errors' => [],
      '#mcp_editor_parents' => ['webhooks', 'endpoints'],
      '#ajax' => [
        'callback' => '::listEditorAjax',
        'wrapper' => 'mcp-webhook-endpoints-wrapper',
      ],
    ];

    // Legacy single-endpoint fields (D4.5: kept visible with a migration
    // notice; webhook_endpoints above is the going-forward mechanism).
    $form['webhooks_legacy'] = [
      '#type' => 'details',
      '#title' => $this->t('Legacy single webhook (deprecated)'),
      '#open' => (bool) $config->get('webhook_url'),
      '#description' => $this->t('These legacy settings are superseded by the endpoints above and are no longer used for delivery. They are retained for review; configure delivery via <em>Reliable webhooks</em> instead, then clear these.'),
      '#tree' => TRUE,
      '#group' => 'tabs',
    ];
    $form['webhooks_legacy']['webhook_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable legacy webhook notifications'),
      '#default_value' => $config->get('webhook_enabled') ?? FALSE,
    ];
    $form['webhooks_legacy']['webhook_url'] = [
      '#type'          => 'url',
      '#title'         => $this->t('Legacy webhook URL (HTTPS required)'),
      '#default_value' => $config->get('webhook_url') ?? '',
    ];
    $form['webhooks_legacy']['webhook_secret_key'] = [
      '#type'          => 'key_select',
      '#title'         => $this->t('Legacy webhook signing secret (HMAC-SHA256)'),
      '#description'   => $this->t('Select a <a href=":url">Key</a> holding the signing secret.', [
        ':url' => '/admin/config/system/keys',
      ]),
      '#default_value' => $config->get('webhook_secret_key') ?? '',
      '#empty_option'  => $this->t('- None -'),
    ];

    $form['broadcast'] = [
      '#type' => 'details',
      '#title' => $this->t('Dashboard broadcast'),
      '#group' => 'tabs',
    ];
    $broadcast = (array) ($config->get('dashboard_broadcast') ?? []);
    $form['broadcast']['dashboard_broadcast_message'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Operator broadcast message'),
      '#description' => $this->t('Shown as a banner on the governance dashboard. Leave empty for none.'),
      '#default_value' => (string) ($broadcast['message'] ?? ''),
      '#maxlength' => 255,
    ];
    $form['broadcast']['dashboard_broadcast_severity'] = [
      '#type' => 'select',
      '#title' => $this->t('Broadcast severity'),
      '#options' => [
        'info' => $this->t('Info'),
        'warning' => $this->t('Warning'),
        'critical' => $this->t('Critical (also shown site-wide to admins)'),
      ],
      '#default_value' => (string) ($broadcast['severity'] ?? 'info'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    // Validate the DLP patterns multi-row editor.
    $dlp_rows = (array) ($form_state->getValue('dlp_patterns_rows') ?? []);
    foreach ($dlp_rows as $i => $row) {
      if (!is_array($row)) {
        continue;
      }
      $label = trim((string) ($row['label'] ?? ''));
      $regex = trim((string) ($row['regex'] ?? ''));
      // A fully blank row is skipped.
      if ($label === '' && $regex === '') {
        continue;
      }
      if ($label === '' || $regex === '') {
        $form_state->setErrorByName(
          "dlp][dlp_patterns_rows][$i][label",
          $this->t(
            'DLP pattern @n is invalid: it must contain both a label and a pattern.',
            ['@n' => (int) $i + 1],
          ),
        );
        continue;
      }
      // Validate the regex by running a test match with the same wrapped form
      // the service uses at runtime.
      $wrapped = McpDlp::wrapPattern($regex);
      if (@preg_match($wrapped, '') === FALSE) {
        $form_state->setErrorByName(
          "dlp][dlp_patterns_rows][$i][regex",
          $this->t(
            'DLP pattern "@label" has an invalid regular expression: <code>@regex</code>.',
            ['@label' => $label, '@regex' => $regex],
          ),
        );
      }
    }

    // Validate the anomaly rules multi-row editor.
    if ($form_state->getValue('anomaly_enabled')) {
      $rule_rows = (array) ($form_state->getValue('anomaly_rules_rows') ?? []);
      $seenRuleIds = [];
      foreach ($rule_rows as $i => $row) {
        if (!is_array($row)) {
          continue;
        }
        $rId = trim((string) ($row['id'] ?? ''));
        $rOp = trim((string) ($row['operation_pattern'] ?? ''));
        $rWin = (int) ($row['window_seconds'] ?? 0);
        $rThr = (int) ($row['threshold'] ?? 0);
        // An entirely blank row is skipped.
        if ($rId === '' && $rOp === '') {
          continue;
        }
        if ($rId === '') {
          $form_state->setErrorByName("anomaly][anomaly_rules_rows][$i][id", $this->t('Anomaly rule @n: id must not be empty.', ['@n' => (int) $i + 1]));
        }
        elseif (!preg_match('/^[a-z0-9_]+$/', $rId)) {
          $form_state->setErrorByName("anomaly][anomaly_rules_rows][$i][id", $this->t('Anomaly rule @n: id must be lowercase letters, numbers and underscores only.', ['@n' => (int) $i + 1]));
        }
        elseif (isset($seenRuleIds[$rId])) {
          $form_state->setErrorByName("anomaly][anomaly_rules_rows][$i][id", $this->t('Duplicate anomaly rule id "@id".', ['@id' => $rId]));
        }
        $seenRuleIds[$rId] = TRUE;
        if ($rOp === '') {
          $form_state->setErrorByName("anomaly][anomaly_rules_rows][$i][operation_pattern", $this->t('Anomaly rule @n: operation_pattern must not be empty.', ['@n' => (int) $i + 1]));
        }
        if ($rWin <= 0) {
          $form_state->setErrorByName("anomaly][anomaly_rules_rows][$i][window_seconds", $this->t('Anomaly rule @n: window must be a positive integer.', ['@n' => (int) $i + 1]));
        }
        if ($rThr <= 0) {
          $form_state->setErrorByName("anomaly][anomaly_rules_rows][$i][threshold", $this->t('Anomaly rule @n: threshold must be a positive integer.', ['@n' => (int) $i + 1]));
        }
      }
    }

    // Validate the alert email address if provided.
    $alertEmail = trim((string) ($form_state->getValue('anomaly_alert_email') ?? ''));
    if ($alertEmail !== '' && !filter_var($alertEmail, FILTER_VALIDATE_EMAIL)) {
      $form_state->setErrorByName('anomaly_alert_email', $this->t('Alert email address is not a valid email address.'));
    }

    // Validate each configured webhook endpoint.
    $keyStorage = $this->entityTypeManager->getStorage('key');
    $endpoints = (array) ($form_state->getValue(['webhooks', 'endpoints']) ?? []);
    $seen_ids = [];
    foreach ($endpoints as $i => $ep) {
      // Skip the editor's Add/Remove button values (non-array siblings).
      if (!is_array($ep)) {
        continue;
      }
      $id = trim((string) ($ep['id'] ?? ''));
      $url = trim((string) ($ep['url'] ?? ''));
      // An entirely blank slot is skipped.
      if ($id === '' && $url === '') {
        continue;
      }
      if ($id === '') {
        $form_state->setErrorByName("webhooks][endpoints][$i][id", $this->t('Endpoint @n needs a machine ID.', ['@n' => $i + 1]));
      }
      elseif (!preg_match('/^[a-z0-9_]+$/', $id)) {
        $form_state->setErrorByName("webhooks][endpoints][$i][id", $this->t('Endpoint @n machine ID must contain only lowercase letters, numbers and underscores.', ['@n' => $i + 1]));
      }
      elseif (isset($seen_ids[$id])) {
        $form_state->setErrorByName("webhooks][endpoints][$i][id", $this->t('Duplicate endpoint machine ID "@id".', ['@id' => $id]));
      }
      $seen_ids[$id] = TRUE;
      if ($url === '' || !str_starts_with($url, 'https://')) {
        $form_state->setErrorByName("webhooks][endpoints][$i][url", $this->t('Endpoint @n URL must use HTTPS.', ['@n' => $i + 1]));
      }
      elseif ($this->isInternalHost($url)) {
        $form_state->setErrorByName("webhooks][endpoints][$i][url", $this->t('Endpoint @n URL points at an internal/loopback host.', ['@n' => $i + 1]));
      }
      $secret = trim((string) ($ep['secret_key'] ?? ''));
      if ($secret !== '' && !$keyStorage->load($secret)) {
        $form_state->setErrorByName("webhooks][endpoints][$i][secret_key", $this->t(
          'Endpoint @n signing key "@key" does not exist.',
          ['@n' => $i + 1, '@key' => $secret],
        ));
      }
    }

    $legacy_url = $form_state->getValue(['webhooks_legacy', 'webhook_url']);
    if ($form_state->getValue(['webhooks_legacy', 'webhook_enabled']) && $legacy_url && !str_starts_with($legacy_url, 'https://')) {
      $form_state->setErrorByName('webhooks_legacy][webhook_url', $this->t('Webhook URL must use HTTPS.'));
    }
  }

  /**
   * Fast (DNS-free) check for an obviously internal/loopback webhook host.
   *
   * @param string $url
   *   The endpoint URL.
   *
   * @return bool
   *   TRUE if the host is localhost or a loopback literal.
   */
  private function isInternalHost(string $url): bool {
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    $host = trim($host, '[]');
    if (in_array($host, ['localhost', '::1', '0.0.0.0'], TRUE)) {
      return TRUE;
    }
    return str_starts_with($host, '127.');
  }

  /**
   * Submit handler: adds a DLP pattern row.
   */
  public function dlpAddRow(array &$form, FormStateInterface $form_state): void {
    $this->addRow($form, $form_state, 'dlp_patterns_rows');
  }

  /**
   * Submit handler: removes a DLP pattern row.
   */
  public function dlpRemoveRow(array &$form, FormStateInterface $form_state): void {
    $this->removeRow($form, $form_state, 'dlp_patterns_rows');
  }

  /**
   * Submit handler: adds an anomaly rule row.
   */
  public function anomalyAddRow(array &$form, FormStateInterface $form_state): void {
    $this->addRow($form, $form_state, 'anomaly_rules_rows');
  }

  /**
   * Submit handler: removes an anomaly rule row.
   */
  public function anomalyRemoveRow(array &$form, FormStateInterface $form_state): void {
    $this->removeRow($form, $form_state, 'anomaly_rules_rows');
  }

  /**
   * Submit handler: adds a webhook endpoint row.
   */
  public function webhookAddRow(array &$form, FormStateInterface $form_state): void {
    $this->addRow($form, $form_state, 'webhook_endpoints_rows');
  }

  /**
   * Submit handler: removes a webhook endpoint row.
   */
  public function webhookRemoveRow(array &$form, FormStateInterface $form_state): void {
    $this->removeRow($form, $form_state, 'webhook_endpoints_rows');
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $split = static fn (string $v): array => array_values(array_filter(array_map('trim', explode("\n", $v))));

    // Assemble the DLP patterns sequence-of-maps from the row editor, dropping
    // rows that lack a label or pattern.
    $dlp_patterns = [];
    foreach ((array) ($form_state->getValue('dlp_patterns_rows') ?? []) as $row) {
      if (!is_array($row)) {
        continue;
      }
      $label = trim((string) ($row['label'] ?? ''));
      $regex = trim((string) ($row['regex'] ?? ''));
      $mask  = trim((string) ($row['mask'] ?? ''));
      if ($label !== '' && $regex !== '') {
        $dlp_patterns[] = [
          'label' => $label,
          'regex' => $regex,
          'mask'  => $mask !== '' ? $mask : '*',
        ];
      }
    }
    // Assemble the anomaly rules sequence-of-maps from the row editor, dropping
    // rows that lack an id or operation pattern.
    $anomaly_rules = [];
    foreach ((array) ($form_state->getValue('anomaly_rules_rows') ?? []) as $row) {
      if (!is_array($row)) {
        continue;
      }
      $rId = trim((string) ($row['id'] ?? ''));
      $rOp = trim((string) ($row['operation_pattern'] ?? ''));
      if ($rId === '' || $rOp === '') {
        continue;
      }
      $anomaly_rules[] = [
        'id'                => $rId,
        'label'             => trim((string) ($row['label'] ?? '')),
        'operation_pattern' => $rOp,
        'window_seconds'    => max(1, (int) ($row['window_seconds'] ?? 300)),
        'threshold'         => max(1, (int) ($row['threshold'] ?? 10)),
        'debounce_seconds'  => max(0, (int) ($row['debounce_seconds'] ?? 3600)),
        'enabled'           => !empty($row['enabled']),
      ];
    }

    // Serialize the webhook endpoint slots into the config sequence, dropping
    // entirely blank slots.
    $webhook_endpoints = [];
    foreach ((array) ($form_state->getValue(['webhooks', 'endpoints']) ?? []) as $ep) {
      // Skip the editor's Add/Remove button values (non-array siblings).
      if (!is_array($ep)) {
        continue;
      }
      $id = trim((string) ($ep['id'] ?? ''));
      $url = trim((string) ($ep['url'] ?? ''));
      if ($id === '' && $url === '') {
        continue;
      }
      $webhook_endpoints[] = [
        'id'             => $id,
        'label'          => trim((string) ($ep['label'] ?? '')),
        'url'            => $url,
        'secret_key'     => trim((string) ($ep['secret_key'] ?? '')),
        'events'         => $split((string) ($ep['events'] ?? '')),
        'enabled'        => (bool) ($ep['enabled'] ?? FALSE),
        'allow_internal' => (bool) ($ep['allow_internal'] ?? FALSE),
      ];
    }

    // An empty textarea clears to [] (falls back to default patterns at runtime
    // via McpDlp::createFromConfig, which calls defaultPatterns() when empty).
    $this->config('mcp_sentinel.settings')
      ->set('enabled', (bool) $form_state->getValue('enabled'))
      ->set('governed_roles', array_values(array_filter($form_state->getValue('governed_roles'))))
      ->set('agent_scopes', $split($form_state->getValue('agent_scopes')))
      ->set('agent_oauth_clients', $split($form_state->getValue('agent_oauth_clients')))
      ->set('governed_role_fallback', (bool) $form_state->getValue('governed_role_fallback'))
      ->set('audit_enabled', (bool) $form_state->getValue('audit_enabled'))
      ->set('audit_log_reads', (bool) $form_state->getValue('audit_log_reads'))
      ->set('audit_retention_days', (int) $form_state->getValue('audit_retention_days'))
      ->set('audit_hash_key', $form_state->getValue('audit_hash_key'))
      ->set('siem_enabled', (bool) $form_state->getValue('siem_enabled'))
      ->set('audit_encryption_profile', (string) ($form_state->getValue('audit_encryption_profile') ?? ''))
      ->set('dlp_enabled', (bool) $form_state->getValue('dlp_enabled'))
      ->set('dlp_mask_mode', (string) ($form_state->getValue('dlp_mask_mode') ?? 'redact'))
      ->set('dlp_patterns', $dlp_patterns)
      ->set('anomaly_enabled', (bool) $form_state->getValue('anomaly_enabled'))
      ->set('anomaly_alert_log', (bool) $form_state->getValue('anomaly_alert_log'))
      ->set('anomaly_alert_email', trim((string) ($form_state->getValue('anomaly_alert_email') ?? '')))
      ->set('anomaly_alert_webhook', (bool) $form_state->getValue('anomaly_alert_webhook'))
      ->set('anomaly_rules', $anomaly_rules)
      ->set('webhook_endpoints', $webhook_endpoints)
      ->set('webhook_delivery_retention_days', (int) $form_state->getValue([
        'webhooks', 'webhook_delivery_retention_days',
      ]))
      ->set('allow_internal_webhook_urls', (bool) $form_state->getValue(['webhooks', 'allow_internal_webhook_urls']))
      ->set('webhook_enabled', (bool) $form_state->getValue(['webhooks_legacy', 'webhook_enabled']))
      ->set('webhook_url', $form_state->getValue(['webhooks_legacy', 'webhook_url']))
      ->set('webhook_secret_key', $form_state->getValue(['webhooks_legacy', 'webhook_secret_key']))
      ->set('dashboard_broadcast', [
        'message' => trim((string) $form_state->getValue('dashboard_broadcast_message')),
        'severity' => (string) $form_state->getValue('dashboard_broadcast_severity'),
      ])
      ->save();

    parent::submitForm($form, $form_state);
  }

}
