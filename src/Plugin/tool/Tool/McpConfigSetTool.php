<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Event\McpDestructiveActionEvent;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpConfigWriteValidator;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Tool\ConfigScopeToolInterface;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Writes top-level keys into a configuration object under MCP Sentinel policy.
 *
 * The write is gated by the resolved profile's allow_config_write flag and the
 * denied_config_types denylist. The object the write would produce is then
 * validated: typed-config validation of the merged data, followed by the config
 * import validators for that one object. A name with no schema is refused
 * unless the profile sets allow_schemaless_config_write. A refusal is written
 * to the audit log as denied_access and reports property paths, never values.
 *
 * Validation runs before the approval event on purpose. It only reads, so it
 * costs nothing to run first, and it keeps an invalid change out of the
 * approval queue: a reviewer is never asked to approve something the site
 * would refuse. The approval executor validates again when it replays a queued
 * change, because the active configuration can move while a request waits.
 *
 * After validation the tool dispatches an McpDestructiveActionEvent so the
 * approval submodule (if enabled and the operation is gated) can queue the
 * change for human approval instead of executing it. The actual config save is
 * audited — and a write to a denied config name is hard-denied — by
 * McpConfigSaveSubscriber on the SAVE event, which also backstops any direct
 * TokenAuthUser config save.
 */
#[Tool(
  id: 'mcp_sentinel_config_set',
  label: new TranslatableMarkup('Set configuration'),
  description: new TranslatableMarkup('Sets one or more top-level keys on a Drupal configuration object. Governed by MCP Sentinel config-write policy; destructive and may require approval.'),
  operation: ToolOperation::Write,
  destructive: TRUE,
  input_definitions: [
    'name' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Config name'),
      description: new TranslatableMarkup('The configuration object name, e.g. system.site.'),
      required: TRUE,
    ),
    'data' => new InputDefinition(
      data_type: 'map',
      label: new TranslatableMarkup('Config values'),
      description: new TranslatableMarkup('A map of top-level config keys to their new values.'),
      required: TRUE,
    ),
  ],
)]
final class McpConfigSetTool extends McpGovernedToolBase implements ConfigScopeToolInterface {

  use McpEntityToolTrait;

  /**
   * The config factory.
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * The MCP Sentinel access checker.
   */
  protected McpAccessChecker $accessChecker;

  /**
   * The MCP Sentinel policy resolver.
   */
  protected McpPolicyResolver $policyResolver;

  /**
   * The event dispatcher.
   */
  protected EventDispatcherInterface $eventDispatcher;

  /**
   * Validates the object a write would produce.
   */
  protected McpConfigWriteValidator $configWriteValidator;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->configFactory = $container->get('config.factory');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    $instance->eventDispatcher = $container->get('event_dispatcher');
    $instance->configWriteValidator = $container->get('mcp_sentinel.config_write_validator');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $name = trim((string) ($values['name'] ?? ''));
    $data = $values['data'] ?? [];
    if ($name === '') {
      return ExecutableResult::failure($this->t('A configuration name is required.'));
    }
    if (!is_array($data) || $data === []) {
      return ExecutableResult::failure($this->t('A non-empty map of config values is required.'));
    }
    $profile = $this->policyResolver->resolve($this->currentUser);
    if ($profile === NULL) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied: no governance profile applies to this account.'));
    }
    if ($rateLimited = $this->checkRateLimit($profile, 'mcp_sentinel_config_set')) {
      return $rateLimited;
    }
    $policyResult = $this->accessChecker->checkConfigAccess($name, 'write', $profile);
    if ($reason = $this->denyReason($policyResult)) {
      $this->logDeniedAccess('mcp_sentinel_config_set', 'config', $name, 'write', $reason);
      return ExecutableResult::failure($this->t('MCP Sentinel denied the config write: @reason', ['@reason' => $reason]));
    }

    // Validate the object this write would produce before anything is queued
    // or saved. The verdict holds property paths and a reason code only.
    $verdict = $this->configWriteValidator->validate($name, $data, $profile->allowsSchemalessConfigWrite());
    if (!$verdict->valid) {
      $this->logDeniedAccess('mcp_sentinel_config_set', 'config', $name, 'write', 'config validation: ' . $verdict->summary());
      return ExecutableResult::failure($this->t('MCP Sentinel refused the config write: @summary.', ['@summary' => $verdict->summary()]));
    }

    // Give the approval submodule a chance to gate this write. A veto means the
    // change was queued for human approval and must not execute now. Fail
    // closed if the dispatcher itself errors.
    try {
      $payload = ['data' => $data];
      if ($verdict->schemaless) {
        // Sealed into the approval manifest. The executor refuses to replay a
        // write to a schema-less name without it.
        $payload['schemaless_allowed'] = TRUE;
      }
      $event = new McpDestructiveActionEvent('config', $name, 'config_import', $this->currentUser, $payload);
      $this->eventDispatcher->dispatch($event, McpDestructiveActionEvent::NAME);
      if ($event->isVetoed()) {
        return ExecutableResult::success(
          $this->t('Configuration change for @name was submitted for approval.', ['@name' => $name]),
          ['name' => $name, 'queued_for_approval' => TRUE],
        );
      }
    }
    catch (\Throwable $e) {
      // An exception message can repeat the submitted values. Log where it
      // came from and tell the caller only that the change was blocked.
      $this->logFailure('approval gate', $name, $e);
      return ExecutableResult::failure($this->t('Configuration change blocked: the approval gate failed. The error has been logged.'));
    }

    try {
      $editable = $this->configFactory->getEditable($name);
      foreach ($data as $key => $value) {
        $editable->set((string) $key, $value);
      }
      // The save triggers McpConfigSaveSubscriber, which audits the diff and
      // hard-denies a write to a denied config name.
      $editable->save();
    }
    catch (\Throwable $e) {
      // The factory caches the mutable object. Drop it, so values that were
      // set but never written cannot ride along with a later save of this
      // name in the same request.
      $this->configFactory->reset($name);
      $this->logFailure('save', $name, $e);
      return ExecutableResult::failure($this->t('Configuration write failed or was blocked by policy. The error has been logged.'));
    }

    return ExecutableResult::success(
      $this->t('Configuration @name updated.', ['@name' => $name]),
      ['name' => $name, 'keys' => array_keys($data)],
    );
  }

  /**
   * Logs a failed stage by exception class and location, never its message.
   */
  private function logFailure(string $stage, string $name, \Throwable $e): void {
    $this->logger->error('Config set (@stage) failed for @name: @type at @file:@line.', [
      '@stage' => $stage,
      '@name' => $name,
      '@type' => get_class($e),
      '@file' => basename($e->getFile()),
      '@line' => $e->getLine(),
    ]);
  }

}
