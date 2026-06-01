<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Enforces MCP Sentinel access control on entity operations.
 *
 * Applies the global master switch (mcp_sentinel.settings:enabled) and then the
 * resolved policy profile's gates and entity allow/deny lists. Works alongside
 * Drupal's core access system — both must allow an operation for it to proceed.
 */
final class McpAccessChecker {

  /**
   * Constructs an McpAccessChecker.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * Checks whether an MCP operation on an entity is permitted under a profile.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being accessed.
   * @param string $operation
   *   The operation (e.g. 'view', 'update', 'create', 'delete').
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile for the requesting account.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   Forbidden if the operation is disallowed; neutral otherwise.
   */
  public function checkEntityAccess(
    EntityInterface $entity,
    string $operation,
    McpPolicyProfileInterface $profile,
  ): AccessResult {
    $entityType = $entity->getEntityTypeId();
    $tags = [
      'config:mcp_sentinel.settings',
      'config:mcp_sentinel.mcp_policy_profile.' . $profile->id(),
    ];

    if (!$this->configFactory->get('mcp_sentinel.settings')->get('enabled')) {
      return AccessResult::forbidden('MCP access is disabled.')->addCacheTags($tags);
    }

    if (in_array($entityType, $profile->getDeniedEntityTypes(), TRUE)) {
      return AccessResult::forbidden(
        "Entity type '{$entityType}' is denied by MCP Sentinel."
      )->addCacheTags($tags);
    }

    $allowed = $profile->getAllowedEntityTypes();
    if ($allowed && !in_array($entityType, $allowed, TRUE)) {
      return AccessResult::forbidden(
        "Entity type '{$entityType}' is not in the MCP Sentinel allowlist."
      )->addCacheTags($tags);
    }

    if ($operation === 'view' && !$profile->allowsRead()) {
      return AccessResult::forbidden(
        'Read operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
    }
    if (in_array($operation, ['update', 'create'], TRUE) && !$profile->allowsWrite()) {
      return AccessResult::forbidden(
        'Write operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
    }
    if ($operation === 'delete' && !$profile->allowsDelete()) {
      return AccessResult::forbidden(
        'Delete operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
    }

    return AccessResult::neutral()->addCacheTags($tags);
  }

  /**
   * Returns JSON:API filter access rules for an entity type under a profile.
   *
   * @param string $entityTypeId
   *   The entity type ID to check.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile for the requesting account.
   *
   * @return array
   *   An array of JSONAPI_FILTER_AMONG_* constant keys to AccessResult values,
   *   or an empty array when the entity type is unrestricted.
   */
  public function getJsonApiFilterAccess(
    string $entityTypeId,
    McpPolicyProfileInterface $profile,
  ): array {
    if (in_array($entityTypeId, $profile->getDeniedEntityTypes(), TRUE)) {
      return [JSONAPI_FILTER_AMONG_ALL => AccessResult::forbidden('Denied by MCP Sentinel.')];
    }
    $allowed = $profile->getAllowedEntityTypes();
    if ($allowed && !in_array($entityTypeId, $allowed, TRUE)) {
      return [JSONAPI_FILTER_AMONG_ALL => AccessResult::forbidden('Not in MCP Sentinel allowlist.')];
    }
    return [];
  }

}
