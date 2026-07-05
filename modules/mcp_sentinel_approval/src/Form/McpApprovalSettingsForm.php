<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Configures which governed operations require human approval, and the TTL.
 *
 * Edits mcp_sentinel_approval.settings — the gated_operations list and the
 * break-glass grant lifetime — so operators can tune the approval gate without
 * editing YAML or using drush config:set.
 */
final class McpApprovalSettingsForm extends ConfigFormBase {

  /**
   * The settings object edited by this form.
   */
  private const SETTINGS = 'mcp_sentinel_approval.settings';

  /**
   * The operations this form manages as checkboxes.
   */
  private const MANAGED_OPERATIONS = ['delete', 'config_import', 'module_disable'];

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'mcp_sentinel_approval_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return [self::SETTINGS];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config(self::SETTINGS);
    $gated = (array) $config->get('gated_operations');

    $form['intro'] = [
      '#type'   => 'item',
      '#markup' => $this->t('When an operation is gated, the governed operation is not executed immediately — it is queued as an approval request for an authorized human to approve or deny. Privilege escalation (<code>grant_mcp_admin</code>) is always gated and cannot be turned off here.'),
    ];

    $form['gated_operations'] = [
      '#type'          => 'checkboxes',
      '#title'         => $this->t('Operations that require approval'),
      '#options'       => [
        'delete'         => $this->t('Delete — bulk entity deletes via the MCP tools'),
        'config_import'  => $this->t('Config write — configuration set/import via the MCP tools'),
        'module_disable' => $this->t('Module disable'),
      ],
      '#default_value' => array_values(array_intersect(self::MANAGED_OPERATIONS, $gated)),
      '#description'   => $this->t('Each checked operation is held for human approval instead of executing. Unchecked operations run immediately, still subject to the policy-profile gates.'),
    ];

    $form['break_glass_ttl_seconds'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Break-glass grant lifetime (seconds)'),
      '#min'           => 60,
      '#max'           => 86400,
      '#default_value' => (int) ($config->get('break_glass_ttl_seconds') ?? 3600),
      '#description'   => $this->t('How long an approved <code>mcp_admin</code> break-glass grant lasts before the cron reaper auto-revokes it. Default 3600 (one hour).'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $selected = array_values(array_filter((array) $form_state->getValue('gated_operations')));

    // Preserve any operations not managed by this form (e.g. a custom op added
    // directly to config) rather than silently dropping them on save.
    $existing = (array) $this->config(self::SETTINGS)->get('gated_operations');
    $preserved = array_values(array_diff($existing, self::MANAGED_OPERATIONS));

    $this->config(self::SETTINGS)
      ->set('gated_operations', array_values(array_unique(array_merge($selected, $preserved))))
      ->set('break_glass_ttl_seconds', (int) $form_state->getValue('break_glass_ttl_seconds'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
