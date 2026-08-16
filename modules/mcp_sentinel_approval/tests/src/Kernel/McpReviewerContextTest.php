<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Reviewer context shows the sealed action against live state.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_approval\Service\McpReviewerContext
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpReviewerContextTest extends KernelTestBase {

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
    'audit_chain',
    'mcp_sentinel',
    'mcp_sentinel_approval',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installEntitySchema('mcp_approval_request');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installSchema('node', ['node_access']);
    $this->installConfig(['filter', 'node', 'mcp_sentinel', 'mcp_sentinel_approval']);
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    Key::create([
      'id' => 'reviewer_context_key',
      'label' => 'Reviewer context key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'reviewer-context-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'reviewer_context_key')
      ->save();
  }

  /**
   * A missing manifest is not visible and cannot be approved.
   *
   * @covers ::build
   */
  public function testMissingManifestIsHidden(): void {
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = $storage->create([
      'requested_by' => 1,
      'operation' => 'delete',
      'entity_type' => 'node',
      'entity_id' => '1',
      'payload' => '{}',
      'status' => McpApprovalRequestInterface::STATUS_PENDING,
      'manifest' => '',
    ]);
    $context = $this->container->get('mcp_sentinel_approval.reviewer_context')->build($request);
    $this->assertFalse($context['visible']);
    $this->assertStringContainsString('no sealed action manifest', $context['message']);
  }

  /**
   * A sealed delete shows the live label and sealed uuid.
   *
   * @covers ::build
   */
  public function testDeleteShowsSealedVersusLive(): void {
    $account = $this->createUser([]);
    $node = Node::create(['type' => 'article', 'title' => 'Review me']);
    $node->save();
    $payload = [
      'entity_type' => 'node',
      'entity_id' => (string) $node->id(),
      'entity_uuid' => (string) $node->uuid(),
      'label' => 'Review me',
      'obligations' => ['log_receipt'],
    ];
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')->tryMint(
      $account,
      'delete',
      [
        'type' => 'node',
        'id' => (string) $node->id(),
        'uuid' => (string) $node->uuid(),
      ],
      $payload,
    );
    $this->assertNotNull($manifest);
    $node->setTitle('Changed after queue');
    $node->save();
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = $storage->create([
      'requested_by' => (int) $account->id(),
      'operation' => 'delete',
      'entity_type' => 'node',
      'entity_id' => (string) $node->id(),
      'payload' => (string) json_encode([
        'label' => 'tampered',
        'obligations' => ['not_from_seal'],
      ]),
      'status' => McpApprovalRequestInterface::STATUS_PENDING,
      'manifest' => $manifest->toJson(),
    ]);
    $context = $this->container->get('mcp_sentinel_approval.reviewer_context')->build($request);
    $this->assertTrue($context['visible']);
    $this->assertSame('delete', $context['operation']);
    $this->assertSame(['log_receipt'], $context['obligations']);
    $fields = array_column($context['rows'], 'field');
    $this->assertContains('uuid', $fields);
    $this->assertContains('label', $fields);
    $byField = array_column($context['rows'], NULL, 'field');
    $this->assertSame('Review me', $byField['label']['sealed']);
    $this->assertSame('Changed after queue', $byField['label']['live']);
  }

  /**
   * Config import redacts secret-looking keys and diffs the rest.
   *
   * @covers ::build
   */
  public function testConfigImportDiffRedactsSecrets(): void {
    $this->config('system.site')->set('name', 'Live name')->save();
    $account = $this->createUser([]);
    $payload = [
      'data' => [
        'name' => 'Sealed name',
        'webhook_secret' => 'should-not-appear',
        'key_provider_settings' => [
          'key_value' => 'nested-secret',
          'safe' => 'visible',
        ],
      ],
    ];
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')->tryMint(
      $account,
      'config_import',
      ['type' => 'config', 'id' => 'system.site'],
      $payload,
    );
    $this->assertNotNull($manifest);
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = $storage->create([
      'requested_by' => (int) $account->id(),
      'operation' => 'config_import',
      'entity_type' => 'config',
      'entity_id' => 'system.site',
      'payload' => (string) json_encode($payload),
      'status' => McpApprovalRequestInterface::STATUS_PENDING,
      'manifest' => $manifest->toJson(),
    ]);
    $context = $this->container->get('mcp_sentinel_approval.reviewer_context')->build($request);
    $this->assertTrue($context['visible']);
    $byField = [];
    foreach ($context['rows'] as $row) {
      $byField[$row['field']] = $row;
    }
    $this->assertSame('Sealed name', $byField['name']['sealed']);
    $this->assertSame('Live name', $byField['name']['live']);
    $this->assertSame('[REDACTED]', $byField['webhook_secret']['sealed']);
    $this->assertStringContainsString('[REDACTED]', $byField['key_provider_settings']['sealed']);
    $this->assertStringNotContainsString('nested-secret', $byField['key_provider_settings']['sealed']);
    $this->assertStringContainsString('visible', $byField['key_provider_settings']['sealed']);
  }

}
