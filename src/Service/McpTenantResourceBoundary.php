<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Access\AccessException;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;

/**
 * Tenant ownership for content a governed agent creates.
 *
 * The stored tenant comes from the sealed network principal. Tool
 * arguments, the hostname, and configuration cannot choose it. An
 * entity with no row keeps the access it already had. The user entity
 * is never recorded.
 */
final class McpTenantResourceBoundary {

  /**
   * Ownership table.
   */
  public const TABLE = 'mcp_sentinel_tenant_resource';

  /**
   * Stored tenant column width. A longer value fails closed.
   */
  private const TENANT_MAX = 128;

  /**
   * Constructs the boundary.
   *
   * @param \Drupal\Core\Database\Connection $connection
   *   The database connection.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   The sealed principal for this request.
   * @param \Drupal\mcp_sentinel\Service\McpDenyExplainer|null $denyExplainer
   *   Operator explainer. Nullable for the deploy window.
   */
  public function __construct(
    private readonly Connection $connection,
    private readonly McpPrincipalContextHolder $holder,
    private readonly ?McpDenyExplainer $denyExplainer = NULL,
  ) {}

  /**
   * Forbids a different tenant from using an owned content entity.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being accessed.
   * @param string $operation
   *   The entity operation.
   *
   * @return \Drupal\Core\Access\AccessResultInterface|null
   *   A forbidden result, or NULL when this boundary has no opinion.
   */
  public function denyOtherTenant(EntityInterface $entity, string $operation): ?AccessResultInterface {
    if ($operation === '' || !$this->inScope($entity)) {
      return NULL;
    }
    $tenant = $this->networkTenant();
    if ($tenant === NULL) {
      return NULL;
    }
    if (strlen($tenant) > self::TENANT_MAX || !$this->tableReady()) {
      return $this->forbidden($entity, $operation);
    }
    $owner = $this->owner($entity);
    if ($owner === NULL || $this->sameTenant($owner, $tenant)) {
      return NULL;
    }
    return $this->forbidden($entity, $operation);
  }

  /**
   * Stops a different tenant from saving or deleting an owned entity.
   *
   * Entity save does not consult hook_entity_access(), so the write
   * path has to refuse here. A new entity has no row yet.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity about to be saved or deleted.
   *
   * @throws \Drupal\Core\Access\AccessException
   *   When the sealed tenant does not own the entity, or the tenant
   *   cannot be stored safely.
   */
  public function assertSameTenant(EntityInterface $entity): void {
    if (!$this->inScope($entity)) {
      return;
    }
    $tenant = $this->requireActingTenant();
    if ($tenant === NULL || $entity->isNew()) {
      return;
    }
    $this->requireTable();
    $owner = $this->owner($entity);
    if ($owner === NULL || $this->sameTenant($owner, $tenant)) {
      return;
    }
    throw new AccessException('tenant_mismatch');
  }

  /**
   * Records the sealed tenant for a content entity it just created.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity that was inserted.
   *
   * @throws \Drupal\Core\Access\AccessException
   *   When the tenant cannot be stored, or another tenant already owns
   *   the entity.
   */
  public function claimNew(EntityInterface $entity): void {
    if (!$this->inScope($entity)) {
      return;
    }
    $tenant = $this->requireActingTenant();
    if ($tenant === NULL) {
      return;
    }
    $this->requireTable();
    $uuid = $this->uuid($entity);
    $owner = $this->owner($entity);
    if ($owner === NULL) {
      $this->connection->insert(self::TABLE)
        ->fields([
          'entity_type' => $entity->getEntityTypeId(),
          'uuid' => $uuid,
          'tenant' => $tenant,
        ])
        ->execute();
      return;
    }
    if (!$this->sameTenant($owner, $tenant)) {
      throw new AccessException('tenant_mismatch');
    }
  }

  /**
   * Makes an access result uncacheable while a network tenant is sealed.
   *
   * The same account can present a different tenant on a later request.
   * A cached allow would cross that boundary.
   *
   * @param \Drupal\Core\Access\AccessResult $result
   *   The access result about to be returned.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   The same result, uncacheable when a network tenant is present.
   */
  public function varyByTenant(AccessResult $result): AccessResult {
    if ($this->networkTenant() === NULL) {
      return $result;
    }
    return $result->setCacheMaxAge(0);
  }

  /**
   * Whether this entity can carry a tenant owner.
   */
  private function inScope(EntityInterface $entity): bool {
    return $entity instanceof ContentEntityInterface
      && $entity->getEntityTypeId() !== 'user';
  }

  /**
   * Sealed network tenant, including a value that is too long to store.
   */
  private function networkTenant(): ?string {
    $context = $this->holder->get();
    if ($context === NULL || !$context->isNetwork()) {
      return NULL;
    }
    $tenant = $context->tenant();
    return $tenant === '' ? NULL : $tenant;
  }

  /**
   * Sealed tenant that is safe to store, or NULL when none is sealed.
   *
   * @throws \Drupal\Core\Access\AccessException
   *   When the sealed tenant is longer than the stored column.
   */
  private function requireActingTenant(): ?string {
    $tenant = $this->networkTenant();
    if ($tenant !== NULL && strlen($tenant) > self::TENANT_MAX) {
      throw new AccessException('tenant_mismatch');
    }
    return $tenant;
  }

  /**
   * Refuses the operation when the ownership table is not there.
   *
   * @throws \Drupal\Core\Access\AccessException
   *   When a network tenant is sealed and the table is missing.
   */
  private function requireTable(): void {
    if (!$this->tableReady()) {
      throw new AccessException('tenant_mismatch');
    }
  }

  /**
   * Whether the ownership table is installed.
   */
  private function tableReady(): bool {
    return $this->connection->schema()->tableExists(self::TABLE);
  }

  /**
   * Stored tenant for an entity, or NULL when it has no owner row.
   */
  private function owner(EntityInterface $entity): ?string {
    $statement = $this->connection->select(self::TABLE, 'ownership')
      ->fields('ownership', ['tenant'])
      ->condition('entity_type', $entity->getEntityTypeId())
      ->condition('uuid', $this->uuid($entity))
      ->range(0, 1)
      ->execute();
    if ($statement === NULL) {
      throw new AccessException('tenant_mismatch');
    }
    $value = $statement->fetchField();
    return is_string($value) && $value !== '' ? $value : NULL;
  }

  /**
   * Entity UUID, refusing a missing or oversized value.
   *
   * @throws \Drupal\Core\Access\AccessException
   *   When the UUID cannot be stored without truncation.
   */
  private function uuid(EntityInterface $entity): string {
    $uuid = $entity->uuid();
    if (!is_string($uuid) || $uuid === '' || strlen($uuid) > self::TENANT_MAX) {
      throw new AccessException('tenant_mismatch');
    }
    return $uuid;
  }

  /**
   * Whether two tenant strings are the same.
   */
  private function sameTenant(string $stored, string $acting): bool {
    if (strlen($stored) !== strlen($acting)) {
      return FALSE;
    }
    return hash_equals($stored, $acting);
  }

  /**
   * Uncacheable tenant denial.
   *
   * @param \Drupal\Core\Entity\EntityInterface|null $entity
   *   The refused entity, when known.
   * @param string $operation
   *   The entity operation that was refused.
   */
  private function forbidden(
    ?EntityInterface $entity = NULL,
    string $operation = '',
  ): AccessResult {
    $entityId = NULL;
    if ($entity !== NULL) {
      $entityId = $entity->isNew() ? '(new)' : (string) $entity->id();
    }
    return AccessResult::forbidden(
      $this->denyExplainer?->refuse(
        'tenant_mismatch',
        NULL,
        TRUE,
        $entity?->getEntityTypeId(),
        $entityId,
        $operation !== '' ? $operation : NULL,
      ) ?? McpDenyExplainer::CALLER_MESSAGE,
    )->setCacheMaxAge(0);
  }

}
