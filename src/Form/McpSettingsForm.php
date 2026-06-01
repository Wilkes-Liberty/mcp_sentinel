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

    $form['status'] = ['#type' => 'fieldset', '#title' => $this->t('MCP Access')];
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
      '#type' => 'fieldset',
      '#title' => $this->t('OAuth agent channel'),
      '#description' => $this->t('Governance triggers when a request is authenticated via the OAuth agent channel (a designated consumer or an agent scope on the access token). See the connector runbook for setup.'),
    ];
    $form['oauth']['agent_scopes'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Agent scopes'),
      '#description' => $this->t('One OAuth scope per line. A token carrying any of these scopes is on the agent channel.'),
      '#default_value' => $lines($config->get('agent_scopes') ?? ['mcp:read', 'mcp:write']),
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

    $form['audit'] = ['#type' => 'fieldset', '#title' => $this->t('Audit Logging')];
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
      '#type' => 'fieldset',
      '#title' => $this->t('Data Loss Prevention (DLP)'),
      '#description' => $this->t('Value-pattern scanning for PII in governed field output. Off by default — opt in by enabling below.'),
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

    // Build the patterns textarea default value from stored config.
    $stored_patterns = $config->get('dlp_patterns');
    $patterns_lines = '';
    if (is_array($stored_patterns) && $stored_patterns !== []) {
      $pattern_rows = [];
      foreach ($stored_patterns as $p) {
        $label = (string) ($p['label'] ?? '');
        $regex = (string) ($p['regex'] ?? '');
        $mask = (string) ($p['mask'] ?? '');
        if ($label !== '' && $regex !== '') {
          $pattern_rows[] = $mask !== '' ? "$label|$regex|$mask" : "$label|$regex";
        }
      }
      $patterns_lines = implode("\n", $pattern_rows);
    }
    $form['dlp']['dlp_patterns'] = [
      '#type'          => 'textarea',
      '#title'         => $this->t('Custom DLP patterns'),
      '#description'   => $this->t('One pattern per line: <code>label|regex|mask</code> (<code>mask</code> is optional, defaults to <code>*</code>). The <code>regex</code> is a PCRE body WITHOUT delimiters — wrapped in <code>#…#i</code> automatically. Example: <code>employee_id|EMP-\d{6}|*</code>. An empty field falls back to the four built-in defaults (email, US phone, SSN, credit card). Invalid regex lines are rejected.'),
      '#default_value' => $patterns_lines,
      '#rows'          => 6,
      '#states'        => ['visible' => ['[name="dlp_enabled"]' => ['checked' => TRUE]]],
    ];

    $form['webhooks'] = ['#type' => 'fieldset', '#title' => $this->t('HTTPS Webhooks')];
    $form['webhooks']['webhook_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable webhook notifications'),
      '#default_value' => $config->get('webhook_enabled') ?? FALSE,
    ];
    $form['webhooks']['webhook_url'] = [
      '#type'          => 'url',
      '#title'         => $this->t('Webhook URL (HTTPS required)'),
      '#default_value' => $config->get('webhook_url') ?? '',
      '#states'        => ['visible' => ['[name="webhook_enabled"]' => ['checked' => TRUE]]],
    ];
    $form['webhooks']['webhook_secret_key'] = [
      '#type'          => 'key_select',
      '#title'         => $this->t('Webhook signing secret (HMAC-SHA256)'),
      '#description'   => $this->t('Select a <a href=":url">Key</a> holding the signing secret. Use a File or Environment key provider so the secret is never written to exported configuration.', [
        ':url' => '/admin/config/system/keys',
      ]),
      '#default_value' => $config->get('webhook_secret_key') ?? '',
      '#empty_option'  => $this->t('- None -'),
      '#states'        => ['visible' => ['[name="webhook_enabled"]' => ['checked' => TRUE]]],
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    // Validate the DLP patterns textarea.
    $raw_patterns = (string) ($form_state->getValue('dlp_patterns') ?? '');
    $lines = array_filter(array_map('trim', explode("\n", $raw_patterns)));
    foreach ($lines as $line_number => $line) {
      $parts = explode('|', $line, 3);
      $label = trim($parts[0]);
      $regex = trim($parts[1] ?? '');
      if ($label === '' || $regex === '') {
        $form_state->setErrorByName(
          'dlp_patterns',
          $this->t(
            'DLP pattern line @n is invalid: each line must contain at least <code>label|regex</code>.',
            ['@n' => (int) $line_number + 1],
          ),
        );
        continue;
      }
      // Validate the regex by running a test match with the same wrapped form
      // the service uses at runtime.
      $wrapped = McpDlp::wrapPattern($regex);
      if (@preg_match($wrapped, '') === FALSE) {
        $form_state->setErrorByName(
          'dlp_patterns',
          $this->t(
            'DLP pattern "@label" has an invalid regular expression: <code>@regex</code>.',
            ['@label' => $label, '@regex' => $regex],
          ),
        );
      }
    }

    $url = $form_state->getValue('webhook_url');
    if ($form_state->getValue('webhook_enabled') && $url && !str_starts_with($url, 'https://')) {
      $form_state->setErrorByName('webhook_url', $this->t('Webhook URL must use HTTPS.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $split = static fn (string $v): array => array_values(array_filter(array_map('trim', explode("\n", $v))));

    // Parse the DLP patterns textarea into the sequence-of-maps config shape.
    $raw_patterns = (string) ($form_state->getValue('dlp_patterns') ?? '');
    $lines = array_filter(array_map('trim', explode("\n", $raw_patterns)));
    $dlp_patterns = [];
    foreach ($lines as $line) {
      $parts = explode('|', $line, 3);
      $label = trim($parts[0]);
      $regex = trim($parts[1] ?? '');
      $mask  = trim($parts[2] ?? '*');
      if ($label !== '' && $regex !== '') {
        $dlp_patterns[] = [
          'label' => $label,
          'regex' => $regex,
          'mask'  => $mask !== '' ? $mask : '*',
        ];
      }
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
      ->set('webhook_enabled', (bool) $form_state->getValue('webhook_enabled'))
      ->set('webhook_url', $form_state->getValue('webhook_url'))
      ->set('webhook_secret_key', $form_state->getValue('webhook_secret_key'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
