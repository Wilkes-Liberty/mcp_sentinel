<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\Core\Session\AnonymousUserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * A queued config change keeps its secret out of the display payload.
 *
 * The approval request stores the change twice: a sealed manifest, which is
 * replayed and has to hold the real values, and a plain payload column kept for
 * display. The second copy must not hold a secret, and withholding it must not
 * change what gets applied on approve.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_approval
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_approval')]
#[RunTestsInSeparateProcesses]
final class McpApprovalConfigSecretTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  use UserCreationTrait;

  private const SECRET = 'S3CR3T-queued-42';

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
    $this->installEntitySchema('path_alias');
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
      'id' => 'agent_config_write',
      'label' => 'Agent config-write profile',
      'roles' => ['mcp_agent'],
      'weight' => 10,
      'allow_config_read' => TRUE,
      'allow_config_write' => TRUE,
    ])->save();

    Key::create([
      'id' => 'seal_key',
      'label' => 'Seal key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'manifest-seal-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'seal_key')->save();
    Key::create([
      'id' => 'agent_key',
      'label' => 'Agent key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'before'],
    ])->save();
  }

  /**
   * The display payload withholds the secret; approve still applies it.
   */
  public function testDisplayPayloadWithholdsTheSecretAndReplayIsIntact(): void {
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($agent);
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_config_set');
    $tool->setInputValue('name', 'key.key.agent_key');
    $tool->setInputValue('data', ['key_provider_settings' => ['key_value' => self::SECRET]]);
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    self::assertTrue($tool->getResult()->getContextValues()['queued_for_approval']);

    $storage = $this->container->get('entity_type.manager')->getStorage('mcp_approval_request');
    $requests = $storage->loadMultiple();
    self::assertCount(1, $requests);
    $request = reset($requests);
    self::assertInstanceOf(McpApprovalRequestInterface::class, $request);

    $stored = (string) $request->get('payload')->value;
    self::assertStringNotContainsString(self::SECRET, $stored);
    self::assertSame('[REDACTED]', $request->getPayload()['data']['key_provider_settings']['key_value'], 'The path is still shown to a reviewer.');

    // No audit row written so far holds it either.
    $rows = $this->container->get('database')->select('audit_chain_log', 'l')->fields('l')->execute()->fetchAll(\PDO::FETCH_ASSOC);
    self::assertStringNotContainsString(self::SECRET, (string) json_encode($rows));

    $current = $this->container->get('current_user');
    $current->setAccount(new AnonymousUserSession());
    $current->setAccount($this->createUser(['approve mcp sentinel operations'], NULL, TRUE));
    $approved = $this->container->get('mcp_sentinel_approval.executor')->approve($request);
    self::assertTrue($approved['executed'], $approved['message']);

    $this->container->get('config.factory')->reset('key.key.agent_key');
    self::assertSame(
      self::SECRET,
      $this->config('key.key.agent_key')->get('key_provider_settings.key_value'),
      'Withholding the display copy must not change what is applied.',
    );
    $rows = $this->container->get('database')->select('audit_chain_log', 'l')->fields('l')->execute()->fetchAll(\PDO::FETCH_ASSOC);
    self::assertStringNotContainsString(self::SECRET, (string) json_encode($rows), 'The approval decision row must not hold it.');
  }

}
