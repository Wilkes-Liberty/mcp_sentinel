<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\Core\Field\FieldDefinitionInterface;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;

/**
 * Field-definition allow/refuse lists for governed entity `fields` maps.
 *
 * Author/owner comes from the token principal, never tool arguments.
 * A reserved content-field name (subject, scope, actor, …) is allowed
 * only when it is a real field on the target bundle and is not a user
 * reference. NEVER_EXEMPT_IDENTITY_KEYS are never allowed. config_set
 * data maps do not use this service.
 */
final class McpEntityFieldReservedAllowlist {

  /**
   * Constructs the allowlist.
   *
   * @param \Drupal\Core\Entity\EntityFieldManagerInterface $entityFieldManager
   *   Field definitions for the target entity type and bundle.
   */
  public function __construct(
    private readonly EntityFieldManagerInterface $entityFieldManager,
  ) {}

  /**
   * Allow and refuse lists for one entity type + bundle.
   *
   * @return array{allow: list<string>, refuse: list<string>}
   *   allow: reserved content-field names that may appear in `fields`.
   *   refuse: owner/author keys and every user-reference field name.
   */
  public function forBundle(string $entityType, string $bundle): array {
    $allow = [];
    $refuse = [];
    foreach (McpPrincipalContext::OWNER_IDENTITY_FIELD_KEYS as $owner) {
      $refuse[] = $owner;
    }
    if ($entityType === '' || $bundle === '') {
      return ['allow' => $allow, 'refuse' => array_values(array_unique($refuse))];
    }
    try {
      $definitions = $this->entityFieldManager->getFieldDefinitions(
        $entityType,
        $bundle,
      );
    }
    catch (\Throwable) {
      return ['allow' => $allow, 'refuse' => array_values(array_unique($refuse))];
    }
    $neverExempt = [];
    foreach (McpPrincipalContext::NEVER_EXEMPT_IDENTITY_KEYS as $reserved) {
      $neverExempt[McpPrincipalContext::normalizeKey($reserved)] = TRUE;
    }
    $reservedNorms = [];
    foreach (McpPrincipalContext::RESERVED_IDENTITY_KEYS as $reserved) {
      $reservedNorms[McpPrincipalContext::normalizeKey($reserved)] = TRUE;
    }
    foreach ($definitions as $name => $definition) {
      if (self::isUserReference($definition)) {
        $refuse[] = (string) $name;
        continue;
      }
      $norm = McpPrincipalContext::normalizeKey((string) $name);
      if (isset($neverExempt[$norm])) {
        continue;
      }
      if (isset($reservedNorms[$norm])) {
        $allow[] = (string) $name;
      }
    }
    return [
      'allow' => array_values(array_unique($allow)),
      'refuse' => array_values(array_unique($refuse)),
    ];
  }

  /**
   * TRUE when the field is an entity_reference targeting user.
   */
  public static function isUserReference(FieldDefinitionInterface $definition): bool {
    $type = $definition->getType();
    if ($type !== 'entity_reference'
      && $type !== 'entity_reference_revisions') {
      return FALSE;
    }
    return $definition->getSetting('target_type') === 'user';
  }

}
