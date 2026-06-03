<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpContentLock;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Check, set, or release a content lock.
 *
 * Agents should call this with action=check before updating a node or media
 * entity, to avoid overwriting content a human is editing.
 */
#[Tool(
  id: 'mcp_sentinel_content_lock',
  label: new TranslatableMarkup('Check or manage content lock'),
  description: new TranslatableMarkup('Check whether a content item is locked (being edited by a human). Always call with action=check before updating a node or media entity. Can also set or release locks.'),
  operation: ToolOperation::Write,
  input_definitions: [
    'action' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Action'),
      description: new TranslatableMarkup('One of: check, lock, release. Defaults to check.'),
      required: FALSE,
      default_value: 'check',
      constraints: ['AllowedValues' => ['choices' => ['check', 'lock', 'release']]],
    ),
    'entity_type' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Entity type'),
      description: new TranslatableMarkup("The entity type ID, e.g. 'node'."),
      required: TRUE,
    ),
    'entity_id' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Entity ID'),
      description: new TranslatableMarkup('The entity ID or UUID.'),
      required: TRUE,
    ),
    'reason' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Reason'),
      description: new TranslatableMarkup('Reason for locking (used with action=lock).'),
      required: FALSE,
    ),
  ],
)]
final class McpContentLockTool extends ToolBase {

  /**
   * The MCP Sentinel content lock service.
   */
  protected McpContentLock $contentLock;

  /**
   * The MCP Sentinel access checker service.
   */
  protected McpAccessChecker $accessChecker;

  /**
   * The MCP Sentinel policy resolver service.
   */
  protected McpPolicyResolver $policyResolver;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->contentLock = $container->get('mcp_sentinel.content_lock');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $action = $values['action'] ?? 'check';
    $entity_type = $values['entity_type'] ?? '';
    $entity_id = (string) ($values['entity_id'] ?? '');

    if ($entity_type === '' || $entity_id === '') {
      return ExecutableResult::failure($this->t('Both entity_type and entity_id are required.'));
    }

    return match ($action) {
      'check' => ExecutableResult::success(
        $this->t('Lock status retrieved for @type/@id.', ['@type' => $entity_type, '@id' => $entity_id]),
        [
          'locked' => $this->contentLock->isLocked($entity_type, $entity_id),
          'lock_info' => $this->contentLock->getLockInfo($entity_type, $entity_id),
        ],
      ),
      'lock' => $this->lock($entity_type, $entity_id, $values['reason'] ?? 'Locked by MCP agent'),
      'release' => $this->release($entity_type, $entity_id),
      default => ExecutableResult::failure(
        $this->t("Unknown action '@action'. Use: check, lock, release.", ['@action' => $action]),
      ),
    };
  }

  /**
   * Sets a lock and returns the result.
   *
   * @param string $entity_type
   *   The entity type ID to lock, e.g. 'node'.
   * @param string $entity_id
   *   The entity ID or UUID to lock.
   * @param string $reason
   *   Human-readable reason recorded with the lock.
   *
   * @return \Drupal\tool\ExecutableResult
   *   A success result confirming the lock was set.
   */
  private function lock(string $entity_type, string $entity_id, string $reason): ExecutableResult {
    $this->contentLock->lock($entity_type, $entity_id, $reason);
    return ExecutableResult::success(
      $this->t('Lock set on @type/@id.', ['@type' => $entity_type, '@id' => $entity_id]),
      ['success' => TRUE],
    );
  }

  /**
   * Releases a lock and returns the result.
   *
   * @param string $entity_type
   *   The entity type ID to unlock, e.g. 'node'.
   * @param string $entity_id
   *   The entity ID or UUID to unlock.
   *
   * @return \Drupal\tool\ExecutableResult
   *   A success result confirming the lock was released.
   */
  private function release(string $entity_type, string $entity_id): ExecutableResult {
    $this->contentLock->release($entity_type, $entity_id);
    return ExecutableResult::success(
      $this->t('Lock released on @type/@id.', ['@type' => $entity_type, '@id' => $entity_id]),
      ['success' => TRUE],
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

    // IP allowlist gate — governed requests only. When a policy profile applies
    // and the client IP is not in the profile's allowlist, deny access.
    // The result is explicitly uncacheable: client IP is not a cache context.
    $profile = $this->policyResolver->resolve($account);
    if ($profile !== NULL && !$this->accessChecker->isClientIpAllowed($profile)) {
      $denied = AccessResult::forbidden('Source IP not permitted by MCP Sentinel policy.')->setCacheMaxAge(0);
      return $return_as_object ? $denied : FALSE;
    }

    return $return_as_object ? $access : $access->isAllowed();
  }

}
