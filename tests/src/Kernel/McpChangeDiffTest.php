<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Database\Statement\FetchAs;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the redaction-aware change diff on entity updates.
 *
 * Verifies that mcp_sentinel_entity_presave captures a 'changes' diff in the
 * audit log metadata for governed updates, that redacted fields are stored as
 * '[REDACTED]', and that unchanged fields are absent.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(\Drupal\mcp_sentinel\Service\McpAuditLogger::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpChangeDiffTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installConfig(['filter', 'node', 'mcp_sentinel']);

    // Enable role-based governance fallback for tests (no OAuth token here).
    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    // Create the governed role.
    Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent'])->save();

    // Create and bind a policy profile that redacts the 'promote' field.
    McpPolicyProfile::create([
      'id'             => 'agent_diff',
      'label'          => 'Agent diff profile',
      'roles'          => ['mcp_agent'],
      'weight'         => 10,
      'allow_write'    => TRUE,
      'redacted_fields' => ['promote'],
    ])->save();

    // Create an 'article' node type.
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
  }

  /**
   * Fetches all audit rows from the database in insertion order.
   *
   * @return array<int, array<string, mixed>>
   *   All rows as associative arrays.
   */
  private function fetchAuditRows(): array {
    return $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchAll(FetchAs::Associative);
  }

  /**
   * Decodes the metadata column of an audit row into an array.
   *
   * @param array<string, mixed> $row
   *   The audit row.
   *
   * @return array<string, mixed>
   *   Decoded metadata.
   */
  private function decodeMetadata(array $row): array {
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) ($row['metadata'] ?? ''));
  }

  /**
   * Creates a governed user and sets it as the current user.
   */
  private function setGovernedCurrentUser(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * An update by a governed agent records 'changes' with old/new title values.
   *
   * @covers ::computeChangeDiff
   */
  public function testChangeDiffCapturesTitleChange(): void {
    $this->setGovernedCurrentUser();

    // Create the node first (this logs a 'create' — we'll skip that row).
    $node = Node::create([
      'type'  => 'article',
      'title' => 'Original title',
    ]);
    $node->save();

    // Clear the log so we start fresh for the update assertion.
    $this->container->get('database')
      ->truncate('mcp_sentinel_audit_log')
      ->execute();

    // Update the title — this triggers hook_entity_presave as an update.
    $node->setTitle('Updated title');
    $node->save();

    $rows = $this->fetchAuditRows();
    $this->assertNotEmpty($rows, 'At least one audit row must be written on update.');

    $last = end($rows);
    $this->assertSame('entity_save', $last['operation']);

    $meta = $this->decodeMetadata($last);
    $this->assertArrayHasKey('changes', $meta, "'changes' key must be present in metadata for an update.");

    $changes = $meta['changes'];
    $this->assertArrayHasKey('title', $changes, "Title change must be recorded in the diff.");
    $this->assertSame('Original title', $changes['title']['old']);
    $this->assertSame('Updated title', $changes['title']['new']);
  }

  /**
   * Redacted fields appear as '[REDACTED]' in the diff, never their values.
   *
   * @covers ::computeChangeDiff
   */
  public function testChangeDiffRedactsConfiguredFields(): void {
    $this->setGovernedCurrentUser();

    $node = Node::create([
      'type'    => 'article',
      'title'   => 'Redaction test',
      'promote' => 0,
    ]);
    $node->save();

    $this->container->get('database')
      ->truncate('mcp_sentinel_audit_log')
      ->execute();

    // Change both title (not redacted) and promote (redacted by the profile).
    $node->setTitle('Redaction test updated');
    $node->set('promote', 1);
    $node->save();

    $rows = $this->fetchAuditRows();
    $this->assertNotEmpty($rows);

    $meta = $this->decodeMetadata(end($rows));
    $this->assertArrayHasKey('changes', $meta);

    $changes = $meta['changes'];

    // 'title' must carry real values.
    $this->assertArrayHasKey('title', $changes);
    $this->assertNotSame('[REDACTED]', $changes['title']['old']);
    $this->assertNotSame('[REDACTED]', $changes['title']['new']);

    // 'promote' must be redacted.
    $this->assertArrayHasKey('promote', $changes, "'promote' must appear in changes (it changed).");
    $this->assertSame('[REDACTED]', $changes['promote']['old']);
    $this->assertSame('[REDACTED]', $changes['promote']['new']);
  }

  /**
   * Unchanged fields must not appear in the diff.
   *
   * @covers ::computeChangeDiff
   */
  public function testChangeDiffOmitsUnchangedFields(): void {
    $this->setGovernedCurrentUser();

    $node = Node::create([
      'type'  => 'article',
      'title' => 'Only title changes',
      'sticky' => 0,
    ]);
    $node->save();

    $this->container->get('database')
      ->truncate('mcp_sentinel_audit_log')
      ->execute();

    // Update only the title; leave 'sticky' alone.
    $node->setTitle('Only title changes — updated');
    $node->save();

    $rows = $this->fetchAuditRows();
    $this->assertNotEmpty($rows);

    $meta = $this->decodeMetadata(end($rows));
    $this->assertArrayHasKey('changes', $meta);

    $changes = $meta['changes'];
    $this->assertArrayHasKey('title', $changes, 'Changed field must appear.');
    $this->assertArrayNotHasKey('sticky', $changes, 'Unchanged field must NOT appear.');
  }

  /**
   * A 'create' operation does NOT produce a 'changes' key.
   *
   * @covers ::computeChangeDiff
   */
  public function testChangeDiffAbsentOnCreate(): void {
    $this->setGovernedCurrentUser();

    Node::create([
      'type'  => 'article',
      'title' => 'Brand-new node',
    ])->save();

    $rows = $this->fetchAuditRows();
    $this->assertNotEmpty($rows);

    // All rows should be for the create; none should have 'changes'.
    foreach ($rows as $row) {
      $meta = $this->decodeMetadata($row);
      $this->assertArrayNotHasKey(
        'changes',
        $meta,
        "'changes' must not be present on a create operation."
      );
    }
  }

  /**
   * The computeChangeDiff() helper can be exercised in isolation.
   *
   * Loads the logger directly and passes a mocked entity pair to verify the
   * helper returns the expected structure without a full presave flow.
   *
   * @covers ::computeChangeDiff
   */
  public function testComputeChangeDiffDirectly(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');

    // Build a real node as the "updated" entity and a clone as "original".
    $node = Node::create([
      'type'  => 'article',
      'title' => 'Before',
    ]);
    // Simulate an already-existing entity (isNew() = FALSE).
    $node->enforceIsNew(FALSE);
    $node->set('nid', 999);

    // The original is a separate instance with the old title.
    $original = Node::create([
      'type'  => 'article',
      'title' => 'Before',
    ]);
    $original->enforceIsNew(FALSE);
    $original->set('nid', 999);

    // Attach original to entity as Drupal core does during presave.
    $node->setOriginal($original);

    // Now change the title on the "new" version.
    $node->setTitle('After');

    $diff = $logger->computeChangeDiff($node, []);
    $this->assertArrayHasKey('title', $diff);
    $this->assertSame('Before', $diff['title']['old']);
    $this->assertSame('After', $diff['title']['new']);
  }

}
