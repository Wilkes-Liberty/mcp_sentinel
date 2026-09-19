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
use Drupal\mcp_sentinel_config_validation_test\EventSubscriber\ImportValidator;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * A queued config write is validated when queued and again when replayed.
 *
 * Covers d.o #3624441 for the approval path. The config set tool validates
 * before it offers a change to the approval gate, so an invalid change is never
 * stored. The executor validates again on approve, because the active
 * configuration can change while a request waits and the merged object is what
 * gets saved.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_approval
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_approval')]
#[RunTestsInSeparateProcesses]
final class McpApprovalConfigValidationTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  use UserCreationTrait;

  private const SCHEMALESS = 'mcp_sentinel_config_validation_test.no_schema';

  /**
   * Lets the opt-in test save the one name that ships no schema.
   *
   * @var string[]
   */
  protected static $configSchemaCheckerExclusions = [self::SCHEMALESS];

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
      'id' => 'config_validation_test_key',
      'label' => 'Config validation test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'config-validation-manifest-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'config_validation_test_key')
      ->save();

    self::assertContains(
      'config_import',
      (array) $this->config('mcp_sentinel_approval.settings')->get('gated_operations'),
      'The shipped approval settings gate config writes.',
    );
  }

  /**
   * Runs the config set tool as a governed agent.
   *
   * @return array{status: bool, message: string, context: array}
   *   What the tool reported.
   */
  private function agentConfigSet(string $name, array $data): array {
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($agent);
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_config_set');
    $tool->setInputValue('name', $name);
    $tool->setInputValue('data', $data);
    $tool->execute();
    return [
      'status' => $tool->getResultStatus(),
      'message' => (string) $tool->getResultMessage(),
      'context' => $tool->getResult()->getContextValues(),
    ];
  }

  /**
   * Approves the newest pending request as a distinct human approver.
   *
   * @return array{executed: bool, error: bool, message: string}
   *   The executor result.
   */
  private function approveNewest(): array {
    $current = $this->container->get('current_user');
    $current->setAccount(new AnonymousUserSession());
    $current->setAccount($this->createUser(['approve mcp sentinel operations'], NULL, TRUE));
    $requests = $this->requests();
    $request = end($requests);
    self::assertInstanceOf(McpApprovalRequestInterface::class, $request);
    self::assertTrue($request->isPending());
    return $this->container->get('mcp_sentinel_approval.executor')->approve($request);
  }

  /**
   * All approval requests, oldest first.
   *
   * @return \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface[]
   *   The requests.
   */
  private function requests(): array {
    $storage = $this->container->get('entity_type.manager')->getStorage('mcp_approval_request');
    $storage->resetCache();
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface[] $requests */
    $requests = $storage->loadMultiple();
    return $requests;
  }

  /**
   * Reads the stored object, bypassing the static cache.
   */
  private function stored(string $name): array {
    $factory = $this->container->get('config.factory');
    $factory->reset($name);
    return $factory->get($name)->getRawData();
  }

  /**
   * How many sealed manifests have been consumed.
   */
  private function consumedKeyCount(): int {
    return (int) $this->container->get('database')->select('mcp_sentinel_manifest_used', 'u')
      ->countQuery()->execute()->fetchField();
  }

  /**
   * An invalid change is refused by the tool and never becomes a request.
   */
  public function testInvalidChangeIsNeverQueued(): void {
    $result = $this->agentConfigSet(ImportValidator::NAME, ['limit' => 99]);
    self::assertFalse($result['status']);
    self::assertStringContainsString('limit', $result['message']);
    self::assertSame([], $this->requests());

    $result = $this->agentConfigSet(self::SCHEMALESS, ['anything' => 'goes']);
    self::assertFalse($result['status']);
    self::assertSame([], $this->requests());
  }

  /**
   * A valid change is queued by the real gate and applied on approve.
   */
  public function testValidChangeIsQueuedThenAppliedOnApprove(): void {
    $result = $this->agentConfigSet(ImportValidator::NAME, ['limit' => 7]);
    self::assertTrue($result['status'], $result['message']);
    self::assertTrue($result['context']['queued_for_approval']);
    self::assertCount(1, $this->requests());
    self::assertSame(5, $this->stored(ImportValidator::NAME)['limit'], 'A queued change is not applied yet.');

    $approved = $this->approveNewest();
    self::assertTrue($approved['executed'], $approved['message']);
    self::assertFalse($approved['error']);
    self::assertSame(7, $this->stored(ImportValidator::NAME)['limit']);
    self::assertSame(1, $this->consumedKeyCount());
  }

  /**
   * A change that stopped validating while it waited is not applied.
   */
  public function testChangeThatNoLongerValidatesIsNotReplayed(): void {
    $result = $this->agentConfigSet(ImportValidator::NAME, ['mode' => 'closed']);
    self::assertTrue($result['context']['queued_for_approval'], $result['message']);

    // The object moves while the request waits: the merged result is now
    // invalid even though the queued keys are fine on their own.
    $this->config(ImportValidator::NAME)->set('limit', 99)->save();

    $approved = $this->approveNewest();
    self::assertFalse($approved['executed']);
    self::assertFalse($approved['error']);
    self::assertStringContainsString('limit', $approved['message']);
    self::assertSame('open', $this->stored(ImportValidator::NAME)['mode']);
    self::assertSame(0, $this->consumedKeyCount(), 'A refused replay does not spend the sealed manifest.');
    $requests = $this->requests();
    self::assertFalse(end($requests)->isPending(), 'The refusal is terminal: retrying cannot make the payload valid.');
  }

  /**
   * A schema-less replay needs the flag the tool sealed into the manifest.
   */
  public function testSchemalessReplayNeedsTheSealedOptIn(): void {
    McpPolicyProfile::load('agent_config_write')->set('allow_schemaless_config_write', TRUE)->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();

    $result = $this->agentConfigSet(self::SCHEMALESS, ['anything' => 'goes']);
    self::assertTrue($result['context']['queued_for_approval'], $result['message']);
    $approved = $this->approveNewest();
    self::assertTrue($approved['executed'], $approved['message']);
    self::assertSame(['anything' => 'goes'], $this->stored(self::SCHEMALESS));

    // The same request shape without the sealed flag, as a request queued
    // before this check existed would have it: refused on approve.
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($agent);
    $payload = ['data' => ['anything' => 'changed']];
    $manifest = $this->container->get('mcp_sentinel.action_manifest_sealer')->tryMint(
      $agent,
      'config_import',
      ['type' => 'config', 'id' => self::SCHEMALESS],
      $payload,
    );
    self::assertNotNull($manifest);
    $this->container->get('entity_type.manager')->getStorage('mcp_approval_request')->create([
      'requested_by' => (int) $agent->id(),
      'operation' => 'config_import',
      'entity_type' => 'config',
      'entity_id' => self::SCHEMALESS,
      'payload' => (string) json_encode($payload),
      'status' => McpApprovalRequestInterface::STATUS_PENDING,
      'manifest' => $manifest->toJson(),
    ])->save();

    $approved = $this->approveNewest();
    self::assertFalse($approved['executed']);
    self::assertStringContainsString('no schema', $approved['message']);
    self::assertSame(['anything' => 'goes'], $this->stored(self::SCHEMALESS));
  }

}
