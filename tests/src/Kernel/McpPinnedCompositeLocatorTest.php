<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\mcp_sentinel\Service\McpPinnedCompositeLocator;
use Drupal\node\Entity\NodeType;
use Drupal\paragraphs\Entity\Paragraph;
use Drupal\paragraphs\Entity\ParagraphsType;

/**
 * Kernel coverage for the published-host pin locator.
 *
 * Exercises the security-critical topology branches of
 * McpPinnedCompositeLocator::analyze() that the JSON:API functional test does
 * not reach: a pin by a draft-only host (in-place edit is not a publish), fan
 * out across multiple published hosts (deny), a nested paragraph chain (deny),
 * and a pin that exists only on a non-default host revision (ignored).
 *
 * @group mcp_sentinel
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPinnedCompositeLocator
 */
final class McpPinnedCompositeLocatorTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'text',
    'filter',
    'node',
    'file',
    'key',
    'encrypt',
    'entity_reference_revisions',
    'paragraphs',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * The paragraph reference field on the host node type.
   */
  private const HOST_FIELD = 'field_paragraphs';

  /**
   * A nested paragraph reference field on the wrapper paragraph type.
   */
  private const NEST_FIELD = 'field_children';

  /**
   * The locator under test.
   */
  private McpPinnedCompositeLocator $locator;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('paragraph');
    $this->installSchema('node', ['node_access']);
    $this->installConfig(['field', 'filter', 'node', 'paragraphs']);

    // Paragraph types: a leaf 'capability' and a 'wrapper' that nests children.
    ParagraphsType::create(['id' => 'capability', 'label' => 'Capability'])->save();
    ParagraphsType::create(['id' => 'wrapper', 'label' => 'Wrapper'])->save();
    FieldStorageConfig::create([
      'field_name' => self::NEST_FIELD,
      'entity_type' => 'paragraph',
      'type' => 'entity_reference_revisions',
      'settings' => ['target_type' => 'paragraph'],
      'cardinality' => -1,
    ])->save();
    FieldConfig::create([
      'field_name' => self::NEST_FIELD,
      'entity_type' => 'paragraph',
      'bundle' => 'wrapper',
      'label' => 'Children',
      'settings' => ['handler' => 'default:paragraph', 'handler_settings' => []],
    ])->save();

    // A 'page' node type with an ERR paragraph field.
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    FieldStorageConfig::create([
      'field_name' => self::HOST_FIELD,
      'entity_type' => 'node',
      'type' => 'entity_reference_revisions',
      'settings' => ['target_type' => 'paragraph'],
      'cardinality' => -1,
    ])->save();
    FieldConfig::create([
      'field_name' => self::HOST_FIELD,
      'entity_type' => 'node',
      'bundle' => 'page',
      'label' => 'Paragraphs',
      'settings' => ['handler' => 'default:paragraph', 'handler_settings' => []],
    ])->save();

    $this->locator = $this->container->get('mcp_sentinel.pinned_composite_locator');
  }

  /**
   * Attaches a paragraph to a page node with the given published status.
   */
  private function makePage(Paragraph $paragraph, bool $published): Node {
    $node = Node::create([
      'type' => 'page',
      'title' => 'Host',
      'status' => $published,
      self::HOST_FIELD => [
        ['target_id' => $paragraph->id(), 'target_revision_id' => $paragraph->getRevisionId()],
      ],
    ]);
    $node->save();
    return $node;
  }

  /**
   * A paragraph pinned by a published node is redirectable.
   *
   * @covers ::analyze
   */
  public function testPublishedHostIsRedirectable(): void {
    $paragraph = Paragraph::create(['type' => 'capability']);
    $paragraph->save();
    $this->makePage($paragraph, TRUE);

    $result = $this->locator->analyze($paragraph, $paragraph->getRevisionId());
    $this->assertTrue($result['pinned_by_published']);
    $this->assertTrue($result['redirectable']);
    $this->assertCount(1, $result['pins']);
    $this->assertSame('node', $result['pins'][0]['host']->getEntityTypeId());
  }

  /**
   * A paragraph pinned only by an unpublished node is not a publish.
   *
   * @covers ::analyze
   */
  public function testDraftHostIsNotPinnedByPublished(): void {
    $paragraph = Paragraph::create(['type' => 'capability']);
    $paragraph->save();
    $this->makePage($paragraph, FALSE);

    $result = $this->locator->analyze($paragraph, $paragraph->getRevisionId());
    $this->assertFalse($result['pinned_by_published'],
      'A draft-only host pin is not an effective publish; in-place edit is allowed.');
    $this->assertFalse($result['redirectable']);
  }

  /**
   * A paragraph pinned by two published hosts is denied (fan-out).
   *
   * @covers ::analyze
   */
  public function testMultipleHostsDenied(): void {
    $paragraph = Paragraph::create(['type' => 'capability']);
    $paragraph->save();
    $this->makePage($paragraph, TRUE);
    $this->makePage($paragraph, TRUE);

    $result = $this->locator->analyze($paragraph, $paragraph->getRevisionId());
    $this->assertTrue($result['pinned_by_published']);
    $this->assertFalse($result['redirectable']);
    $this->assertContains('multi_host', $result['reasons']);
  }

  /**
   * A nested paragraph reached through a wrapper is denied (needs re-pinning).
   *
   * @covers ::analyze
   */
  public function testNestedChainDenied(): void {
    $leaf = Paragraph::create(['type' => 'capability']);
    $leaf->save();
    $wrapper = Paragraph::create([
      'type' => 'wrapper',
      self::NEST_FIELD => [
        ['target_id' => $leaf->id(), 'target_revision_id' => $leaf->getRevisionId()],
      ],
    ]);
    $wrapper->save();
    $this->makePage($wrapper, TRUE);

    $result = $this->locator->analyze($leaf, $leaf->getRevisionId());
    $this->assertTrue($result['pinned_by_published'],
      'The leaf is transitively pinned by a published node.');
    $this->assertFalse($result['redirectable']);
    $this->assertContains('nested', $result['reasons']);
  }

  /**
   * An unreferenced paragraph has no published host pin.
   *
   * @covers ::analyze
   */
  public function testOrphanParagraphNotPinned(): void {
    $paragraph = Paragraph::create(['type' => 'capability']);
    $paragraph->save();

    $result = $this->locator->analyze($paragraph, $paragraph->getRevisionId());
    $this->assertFalse($result['pinned_by_published']);
    $this->assertFalse($result['redirectable']);
  }

  /**
   * A pin present only on a non-default host revision is ignored.
   *
   * @covers ::analyze
   */
  public function testNonDefaultRevisionPinIgnored(): void {
    // Published node pins revision R1 of the paragraph.
    $paragraph = Paragraph::create(['type' => 'capability']);
    $paragraph->save();
    $r1 = $paragraph->getRevisionId();
    $node = $this->makePage($paragraph, TRUE);

    // A later NON-default (forward) node revision pins a new paragraph revision
    // R2; the default revision still pins R1.
    $paragraph->setNewRevision(TRUE);
    $paragraph->save();
    $r2 = $paragraph->getRevisionId();
    $node->setNewRevision(TRUE);
    $node->isDefaultRevision(FALSE);
    $node->set(self::HOST_FIELD, [
      ['target_id' => $paragraph->id(), 'target_revision_id' => $r2],
    ]);
    $node->save();

    // R2 is pinned only by a non-default revision → not pinned by a published
    // default revision.
    $this->assertNotEquals($r1, $r2);
    $result = $this->locator->analyze($paragraph, $r2);
    $this->assertFalse($result['pinned_by_published'],
      'A pin on a non-default (forward) host revision is not an effective publish.');
  }

}
