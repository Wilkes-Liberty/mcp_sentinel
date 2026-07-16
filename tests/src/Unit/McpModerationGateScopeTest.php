<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\mcp_sentinel\Service\McpModerationGate;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Unit tests for which entities the publish gate governs.
 *
 * `deny_publish` means "an agent must not make content publicly visible without
 * a human". Two kinds of publishable entity fall outside that meaning, and
 * governing them turns an ordinary content write into silent data loss:
 * composite children (a paragraph renders only if its host does, and is saved
 * as a side effect of saving the host) and routing metadata (Pathauto mints a
 * path alias as a side effect of saving a node).
 *
 * The default is closed: an entity type that matches no exemption is governed,
 * so an unfamiliar publishable entity is gated rather than silently exempt.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpModerationGate
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpModerationGate::class)]
#[Group('mcp_sentinel')]
final class McpModerationGateScopeTest extends UnitTestCase {

  /**
   * Builds an entity whose type reports the given id and parent-type field.
   *
   * @param string $entity_type_id
   *   The entity type id to report.
   * @param string|null $parent_type_field
   *   The 'entity_revision_parent_type_field' annotation value, or NULL when
   *   the entity type declares none (i.e. it is not a composite child).
   *
   * @return \Drupal\Core\Entity\EntityInterface
   *   The mocked entity.
   */
  private function mockEntity(string $entity_type_id, ?string $parent_type_field = NULL): EntityInterface {
    $entity_type = $this->createMock(EntityTypeInterface::class);
    $entity_type->method('get')
      ->with('entity_revision_parent_type_field')
      ->willReturn($parent_type_field);

    $entity = $this->createMock(EntityInterface::class);
    $entity->method('getEntityTypeId')->willReturn($entity_type_id);
    $entity->method('getEntityType')->willReturn($entity_type);

    return $entity;
  }

  /**
   * Entity types the gate governs, and those it must leave alone.
   *
   * @return array<string, array{string, string|null, bool}>
   *   Case name => [entity type id, parent-type field, expected governed].
   */
  public static function scopeProvider(): array {
    return [
      // Editorial content: the gate's actual subject.
      'node is governed' => ['node', NULL, TRUE],
      'taxonomy term is governed' => ['taxonomy_term', NULL, TRUE],
      'media is governed' => ['media', NULL, TRUE],
      'block content is governed' => ['block_content', NULL, TRUE],
      'menu link is governed' => ['menu_link_content', NULL, TRUE],
      'redirect is governed' => ['redirect', NULL, TRUE],
      // Composite children: never published in their own right, and saved as a
      // side effect of saving the host.
      'paragraph is not governed' => ['paragraph', 'parent_type', FALSE],
      // The rule is structural, not a list of known module names: anything
      // declaring a parent-type field is a composite child.
      'any composite child is not governed' => ['some_contrib_child', 'parent_type', FALSE],
      // Routing metadata: status means "is this alias active", and the aliased
      // path's own access still decides what a visitor may see.
      'path alias is not governed' => ['path_alias', NULL, FALSE],
      // Fail closed: an unfamiliar publishable type stays governed.
      'unknown type is governed' => ['some_future_entity', NULL, TRUE],
    ];
  }

  /**
   * The gate governs editorial content and exempts side-effect entities.
   *
   * @dataProvider scopeProvider
   */
  #[DataProvider('scopeProvider')]
  public function testGovernsPublishedStatus(string $entity_type_id, ?string $parent_type_field, bool $expected): void {
    $gate = new McpModerationGate();
    $entity = $this->mockEntity($entity_type_id, $parent_type_field);

    $this->assertSame(
      $expected,
      $gate->governsPublishedStatus($entity),
      sprintf('Expected the publish gate to %s "%s".', $expected ? 'govern' : 'leave alone', $entity_type_id)
    );
  }

}
