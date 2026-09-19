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
use Drupal\tool\Tool\ToolInterface;
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
   * Ordinary config that can hold a nested secret without being secret-bearing.
   */
  private const NAME = 'mcp_sentinel_config_validation_test.settings';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel', 'mcp_sentinel_approval',
    'mcp_sentinel_config_validation_test',
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
    $this->installConfig([
      'system',
      'mcp_sentinel',
      'mcp_sentinel_approval',
      'mcp_sentinel_config_validation_test',
    ]);

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
   * Runs the config set tool as a governed agent.
   */
  private function agentConfigSet(string $name, array $data): ToolInterface {
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($agent);
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_config_set');
    $tool->setInputValue('name', $name);
    $tool->setInputValue('data', $data);
    $tool->execute();
    return $tool;
  }

  /**
   * Every audit row, serialized.
   */
  private function auditText(): string {
    return (string) json_encode($this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')->execute()->fetchAll(\PDO::FETCH_ASSOC));
  }

  /**
   * The display payload withholds a nested secret; approve still applies it.
   */
  public function testDisplayPayloadWithholdsTheSecretAndReplayIsIntact(): void {
    $tool = $this->agentConfigSet(self::NAME, ['nested' => ['label' => 'visible', 'token' => self::SECRET]]);
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    self::assertTrue($tool->getResult()->getContextValues()['queued_for_approval']);

    $storage = $this->container->get('entity_type.manager')->getStorage('mcp_approval_request');
    $requests = $storage->loadMultiple();
    self::assertCount(1, $requests);
    $request = reset($requests);
    self::assertInstanceOf(McpApprovalRequestInterface::class, $request);

    self::assertStringNotContainsString(self::SECRET, (string) $request->get('payload')->value);
    $shown = $request->getPayload()['data']['nested'];
    self::assertSame('[REDACTED]', $shown['token'], 'The path is still shown.');
    self::assertSame('visible', $shown['label'], 'Ordinary values are still shown.');
    self::assertStringNotContainsString(self::SECRET, $this->auditText());

    // What the reviewer is shown goes through the same redactor.
    $context = $this->container->get('mcp_sentinel_approval.reviewer_context')->build($request);
    self::assertTrue($context['visible']);
    self::assertNotEmpty($context['rows'], 'The changed key still gets a row.');
    self::assertStringNotContainsString(self::SECRET, (string) json_encode($context));
    self::assertStringContainsString('visible', (string) json_encode($context));

    $current = $this->container->get('current_user');
    $current->setAccount(new AnonymousUserSession());
    $current->setAccount($this->createUser(['approve mcp sentinel operations'], NULL, TRUE));
    $approved = $this->container->get('mcp_sentinel_approval.executor')->approve($request);
    self::assertTrue($approved['executed'], $approved['message']);

    $this->container->get('config.factory')->reset(self::NAME);
    self::assertSame(
      self::SECRET,
      $this->config(self::NAME)->get('nested.token'),
      'Withholding the display copy must not change what is applied.',
    );
    self::assertStringNotContainsString(self::SECRET, $this->auditText(), 'No audit row may hold it, the approval decision included.');
  }

  /**
   * A write to a secret-bearing name is refused outright and never queued.
   */
  public function testSecretBearingNameIsRefusedAndNeverQueued(): void {
    foreach (['key.key.agent_key', 'encrypt.profile.any', 'simple_oauth.settings', 'consumer.any'] as $name) {
      $tool = $this->agentConfigSet($name, ['key_provider_settings' => ['key_value' => self::SECRET]]);
      self::assertFalse($tool->getResultStatus(), $name);
      self::assertSame(
        'MCP Sentinel refused the config write: this configuration holds secrets and cannot be written through a governed tool.',
        (string) $tool->getResultMessage(),
        $name,
      );
    }
    self::assertSame([], $this->container->get('entity_type.manager')->getStorage('mcp_approval_request')->loadMultiple(), 'Nothing is stored in the approval tables.');
    $this->container->get('config.factory')->reset('key.key.agent_key');
    self::assertSame('before', $this->config('key.key.agent_key')->get('key_provider_settings.key_value'));
    self::assertStringNotContainsString(self::SECRET, $this->auditText());
    self::assertSame(4, (int) $this->container->get('database')->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')->countQuery()->execute()->fetchField());
  }

  /**
   * A secret-bearing request already in the queue is shown without values.
   *
   * Requests queued before the tool refused such names can still be pending.
   */
  public function testReviewerShowsStructureOnlyForSecretBearingName(): void {
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($agent);
    $payload = ['data' => ['label' => 'Renamed', 'key_provider_settings' => ['key_value' => self::SECRET]]];
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')->tryMint(
      $agent,
      'config_import',
      ['type' => 'config', 'id' => 'key.key.agent_key'],
      $payload,
    );
    self::assertNotNull($manifest);
    $request = $this->container->get('entity_type.manager')->getStorage('mcp_approval_request')->create([
      'requested_by' => (int) $agent->id(),
      'operation' => 'config_import',
      'entity_type' => 'config',
      'entity_id' => 'key.key.agent_key',
      'payload' => '{}',
      'status' => McpApprovalRequestInterface::STATUS_PENDING,
      'manifest' => $manifest->toJson(),
    ]);
    $request->save();
    self::assertInstanceOf(McpApprovalRequestInterface::class, $request);

    $context = $this->container->get('mcp_sentinel_approval.reviewer_context')->build($request);
    $text = (string) json_encode($context);
    self::assertTrue($context['visible']);
    self::assertStringNotContainsString(self::SECRET, $text);
    self::assertStringNotContainsString('before', $text, 'The live secret is withheld as well.');
    self::assertStringNotContainsString('Renamed', $text, 'A secret-bearing name shows no values at all.');
    self::assertStringNotContainsString('Agent key', $text, 'That covers the live side too, ordinary values included.');
    $fields = array_column($context['rows'], 'field');
    self::assertContains('key_provider_settings', $fields);
    self::assertContains('label', $fields);
  }

}
