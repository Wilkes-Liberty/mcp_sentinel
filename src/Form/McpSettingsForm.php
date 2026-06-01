<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
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
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = parent::create($container);
    $instance->entityTypeManager = $container->get('entity_type.manager');
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

    $this->config('mcp_sentinel.settings')
      ->set('enabled', (bool) $form_state->getValue('enabled'))
      ->set('governed_roles', array_values(array_filter($form_state->getValue('governed_roles'))))
      ->set('agent_scopes', $split($form_state->getValue('agent_scopes')))
      ->set('agent_oauth_clients', $split($form_state->getValue('agent_oauth_clients')))
      ->set('governed_role_fallback', (bool) $form_state->getValue('governed_role_fallback'))
      ->set('audit_enabled', (bool) $form_state->getValue('audit_enabled'))
      ->set('audit_log_reads', (bool) $form_state->getValue('audit_log_reads'))
      ->set('audit_retention_days', (int) $form_state->getValue('audit_retention_days'))
      ->set('webhook_enabled', (bool) $form_state->getValue('webhook_enabled'))
      ->set('webhook_url', $form_state->getValue('webhook_url'))
      ->set('webhook_secret_key', $form_state->getValue('webhook_secret_key'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
