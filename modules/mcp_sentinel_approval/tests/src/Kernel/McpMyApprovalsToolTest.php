<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\Core\Session\AnonymousUserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * My-approvals returns only the acting account's requests, never the payload.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_approval
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_approval')]
#[RunTestsInSeparateProcesses]
final class McpMyApprovalsToolTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;

  private const SECRET = 'S3CR3T-approval-payload';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel', 'mcp_sentinel_approval',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('mcp_approval_request');
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel_approval', ['mcp_sentinel_manifest_used']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['system', 'mcp_sentinel', 'mcp_sentinel_approval']);

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();
    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();
    McpPolicyProfile::create([
      'id' => 'agent_profile',
      'label' => 'Agent',
      'roles' => ['mcp_agent'],
      'weight' => 10,
      'allow_config_write' => TRUE,
    ])->save();
  }

  /**
   * Seeds one pending request for an account.
   */
  private function seedRequest(int $uid, string $target): McpApprovalRequestInterface {
    $storage = $this->container->get('entity_type.manager')->getStorage('mcp_approval_request');
    $request = $storage->create([
      'requested_by' => $uid,
      'operation' => 'config_import',
      'entity_type' => 'config',
      'entity_id' => $target,
      'payload' => json_encode(['data' => ['token' => self::SECRET]]),
      'manifest' => '{"token":"' . self::SECRET . '"}',
      'status' => McpApprovalRequestInterface::STATUS_PENDING,
    ]);
    $request->save();
    self::assertInstanceOf(McpApprovalRequestInterface::class, $request);
    return $request;
  }

  /**
   * The acting account sees only its own rows, never the payload or manifest.
   */
  public function testOwnRequestsOnlyAndNoPayload(): void {
    // First created user is uid 1 and bypasses access checks.
    $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $other = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $mine = $this->seedRequest((int) $agent->id(), 'system.site');
    $theirs = $this->seedRequest((int) $other->id(), 'system.theme');

    $this->container->get('current_user')->setAccount($agent);
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_my_approvals');
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();
    $text = (string) json_encode($values);
    self::assertSame(1, $values['count']);
    self::assertSame([(int) $mine->id()], array_column($values['requests'], 'id'));
    self::assertSame('config:system.site', $values['requests'][0]['target']);
    self::assertSame('pending', $values['requests'][0]['status']);
    self::assertNotContains((int) $theirs->id(), array_column($values['requests'], 'id'));
    self::assertStringNotContainsString(self::SECRET, $text);
    self::assertArrayNotHasKey('payload', $values['requests'][0]);
    self::assertArrayNotHasKey('manifest', $values['requests'][0]);

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_my_approvals');
    $tool->execute();
    self::assertFalse($tool->getResultStatus());
  }

}
