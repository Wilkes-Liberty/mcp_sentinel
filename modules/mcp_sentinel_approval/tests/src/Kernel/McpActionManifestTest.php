<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Sealed manifests mint on queue when the signing key resolves.
 *
 * Slice 2 ships dark: a missing key stores nothing, and a present
 * seal is not required for execution.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpActionManifestTest extends KernelTestBase {

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
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installConfig([
      'filter',
      'node',
      'mcp_sentinel',
      'mcp_sentinel_approval',
    ]);

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent']);
    $role->grantPermission('delete any article content');
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    McpPolicyProfile::create([
      'id' => 'agent_delete',
      'label' => 'Agent delete profile',
      'roles' => ['mcp_agent'],
      'weight' => 10,
      'allow_write' => TRUE,
      'allow_delete' => TRUE,
    ])->save();

    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
  }

  /**
   * Without a signing key the request still queues and has no manifest.
   */
  public function testMissingKeyQueuesWithoutManifest(): void {
    $this->setGovernedCurrentUser();
    $node = Node::create(['type' => 'article', 'title' => 'No key']);
    $node->save();
    $this->runBulkDelete((int) $node->id());

    $requests = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request')
      ->loadMultiple();
    $this->assertCount(1, $requests);
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($requests);
    $this->assertSame('', $request->getSealedManifest());
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($node->id()),
    );
  }

  /**
   * A resolvable key stores a verifiable manifest on the request.
   */
  public function testSigningKeyMintsVerifiableManifest(): void {
    $this->configureSigningKey();
    $this->setGovernedCurrentUser();
    $node = Node::create(['type' => 'article', 'title' => 'Sealed']);
    $node->save();
    $this->runBulkDelete((int) $node->id());

    $requests = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request')
      ->loadMultiple();
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($requests);
    $sealed = $request->getSealedManifest();
    $this->assertNotSame('', $sealed);

    /** @var \Drupal\mcp_sentinel\Service\McpActionManifestSealer $sealer */
    $sealer = $this->container->get('mcp_sentinel.action_manifest_sealer');
    $manifest = $sealer->open($sealed);
    $this->assertNotNull($manifest);
    $this->assertSame('delete', $manifest->operation());
    $this->assertSame('node', $manifest->target()['type']);
    $this->assertSame((string) $node->id(), $manifest->target()['id']);
    $this->assertSame((string) $node->uuid(), $manifest->target()['uuid']);
    $this->assertContains('target_uuid', $manifest->preconditions());
    $this->assertStringStartsWith('hmac-sha256:', $manifest->seal());

    $tampered = json_decode($sealed, TRUE);
    $tampered['target']['id'] = '999';
    $this->assertNull($sealer->open((string) json_encode($tampered)));
  }

  /**
   * Execution still follows the unsealed payload (slice 2 is dark).
   */
  public function testSealedManifestDoesNotChangeExecution(): void {
    $this->configureSigningKey();
    $this->setGovernedCurrentUser();
    $node = Node::create(['type' => 'article', 'title' => 'Still executes']);
    $node->save();
    $nid = (int) $node->id();
    $this->runBulkDelete($nid);

    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_approval_request');
    $loaded = $storage->loadMultiple();
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request */
    $request = reset($loaded);
    $this->assertNotSame('', $request->getSealedManifest());

    $result = $this->container->get('mcp_sentinel_approval.executor')->approve($request);
    $this->assertTrue($result['executed']);
    $this->assertNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
    );
  }

  /**
   * Configures the audit-chain signing key the sealer shares with evidence.
   */
  private function configureSigningKey(): void {
    Key::create([
      'id' => 'manifest_test_key',
      'label' => 'Manifest test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'manifest-seal-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'manifest_test_key')
      ->save();
  }

  /**
   * Sets a governed user with delete rights as the current user.
   */
  private function setGovernedCurrentUser(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Runs the bulk delete tool against one node id.
   *
   * @param int $nid
   *   The node id.
   */
  private function runBulkDelete(int $nid): void {
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'delete');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', [(string) $nid]);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();
  }

}
