<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpConfigSecretRedactor;
use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Tool\ConfigScopeToolInterface;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reads a single configuration object under MCP Sentinel governance.
 *
 * The read is gated by the resolved policy profile's allow_config_read flag and
 * its denied_config_types denylist. A successful read is audited as
 * 'config_read' (suppressed unless audit_log_reads is on, like entity reads).
 */
#[Tool(
  id: 'mcp_sentinel_config_get',
  label: new TranslatableMarkup('Get configuration'),
  description: new TranslatableMarkup('Returns the values of a single Drupal configuration object (e.g. system.site). Governed by MCP Sentinel config-read policy.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'name' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Config name'),
      description: new TranslatableMarkup('The configuration object name, e.g. system.site.'),
      required: TRUE,
    ),
  ],
)]
final class McpConfigGetTool extends McpGovernedToolBase implements ConfigScopeToolInterface {

  use McpEntityToolTrait;

  /**
   * Config names this tool reads.
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * Withholds secrets held in configuration.
   */
  protected McpConfigSecretRedactor $configSecrets;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->configFactory = $container->get('config.factory');
    $instance->configSecrets = $container->get('mcp_sentinel.config_secret_redactor');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $name = trim((string) ($values['name'] ?? ''));
    if ($name === '') {
      return ExecutableResult::failure($this->t('A configuration name is required.'));
    }
    $profile = $this->governancePolicyResolver?->resolve($this->currentUser);
    if ($profile === NULL) {
      return ExecutableResult::failure($this->t('@msg', [
        '@msg' => $this->governanceDenyExplainer?->refuse(
          'MCP Sentinel denied: no governance profile applies to this account.',
        ) ?? McpDenyExplainer::CALLER_MESSAGE,
      ]));
    }
    if ($rateLimited = $this->checkRateLimit($profile, 'mcp_sentinel_config_get')) {
      return $rateLimited;
    }
    $policyResult = $this->governanceAccessChecker->checkConfigAccess($name, 'read', $profile, FALSE);
    if ($reason = $this->denyReason($policyResult)) {
      $this->logDeniedAccess('mcp_sentinel_config_get', 'config', $name, 'read', $reason);
      return ExecutableResult::failure($this->t('MCP access is denied.'));
    }

    // Secrets are withheld before the data leaves this method. A value under
    // a sensitive key name is masked at any depth, and a name that holds
    // secrets by nature returns its structure only. The DLP pass that follows
    // in execute() matches patterns; it cannot know a key is a secret.
    $raw = $this->configFactory->get($name)->getRawData();
    $withheld = $this->configSecrets->isSecretBearing($name);
    $data = $this->configSecrets->redactForName($name, $raw, $profile->getRedactedFields());
    $this->governanceAuditLogger?->log('config_read', [
      'entity_type' => 'config',
      'id' => $name,
    ]);

    $context = ['name' => $name, 'data' => $data];
    if ($withheld) {
      // Tell the caller the markers are a policy, not the stored values.
      $context['values_withheld'] = TRUE;
    }
    return ExecutableResult::success(
      $this->t('Configuration @name read.', ['@name' => $name]),
      $context,
    );
  }

}
