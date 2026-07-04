<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Event\McpDestructiveActionEvent;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Tool\ConfigScopeToolInterface;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Writes top-level keys into a configuration object under MCP Sentinel policy.
 *
 * The write is gated by the resolved profile's allow_config_write flag and the
 * denied_config_types denylist. Before the write the tool dispatches an
 * McpDestructiveActionEvent so the approval submodule (if enabled and the
 * operation is gated) can queue the change for human approval instead of
 * executing it. The actual config save is audited — and a write to a denied
 * config name is hard-denied — by McpConfigSaveSubscriber on the SAVE event,
 * which also backstops any direct TokenAuthUser config save.
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
final class McpConfigSetTool extends ToolBase implements ConfigScopeToolInterface {

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
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->configFactory = $container->get('config.factory');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    $instance->eventDispatcher = $container->get('event_dispatcher');
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

    // Give the approval submodule a chance to gate this write. A veto means the
    // change was queued for human approval and must not execute now. Fail
    // closed if the dispatcher itself errors.
    try {
      $event = new McpDestructiveActionEvent('config', $name, 'config_import', $this->currentUser, ['data' => $data]);
      $this->eventDispatcher->dispatch($event);
      if ($event->isVetoed()) {
        return ExecutableResult::success(
          $this->t('Configuration change for @name was submitted for approval.', ['@name' => $name]),
          ['name' => $name, 'queued_for_approval' => TRUE],
        );
      }
    }
    catch (\Throwable $e) {
      return ExecutableResult::failure($this->t('Configuration change blocked: @message', ['@message' => $e->getMessage()]));
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
    catch (\Exception $e) {
      return ExecutableResult::failure($this->t('Configuration write failed: @message', ['@message' => $e->getMessage()]));
    }

    return ExecutableResult::success(
      $this->t('Configuration @name updated.', ['@name' => $name]),
      ['name' => $name, 'keys' => array_keys($data)],
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(array $values, AccountInterface $account, bool $return_as_object = FALSE): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission($account, 'access mcp sentinel context');
    if (!$access->isAllowed()) {
      return $return_as_object ? $access : FALSE;
    }
    $profile = $this->policyResolver->resolve($account);
    if ($profile !== NULL && !$this->accessChecker->isClientIpAllowed($profile)) {
      $denied = AccessResult::forbidden('Source IP not permitted by MCP Sentinel policy.')->setCacheMaxAge(0);
      return $return_as_object ? $denied : FALSE;
    }
    return $return_as_object ? $access : $access->isAllowed();
  }

}
