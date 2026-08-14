<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_server\Kernel;

use Drupal\Core\Cache\CacheTagsInvalidatorInterface;
use Drupal\Core\Config\Entity\ConfigEntityInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Tool\McpToolScopeResolver;
use Drupal\mcp_sentinel_server\Drush\Commands\McpSentinelServerCommands;
use Drupal\user\RoleInterface;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * Tests fail-closed setup preflight and rollback behavior.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_server
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpSentinelServerCommands::class)]
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_server')]
#[RunTestsInSeparateProcesses]
final class McpSentinelServerCommandsTest extends KernelTestBase {

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
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Production setup refuses to write when OAuth is unavailable.
   */
  public function testProductionSetupRequiresOauthBeforeStorageWrites(): void {
    $moduleHandler = $this->moduleHandler([
      'mcp_server_tool_bridge' => TRUE,
      'mcp_server_oauth' => FALSE,
    ]);
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->expects($this->never())->method('getStorage');

    $command = $this->command($entityTypeManager, $moduleHandler);

    $this->assertSame(1, $command->setup());
  }

  /**
   * A missing required scope aborts before any registration is saved.
   */
  public function testMissingRequiredScopeDoesNotPartiallyRegister(): void {
    $this->config('mcp_sentinel.settings')
      ->set('agent_scopes', ['mcp_read'])
      ->save();
    $saved = 0;
    $storage = $this->registrationStorage($saved);
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->with('mcp_tool_config')->willReturn($storage);

    $command = $this->command(
      $entityTypeManager,
      $this->moduleHandler([
        'mcp_server_tool_bridge' => TRUE,
        'mcp_server_oauth' => TRUE,
      ]),
    );

    $this->assertSame(1, $command->setup());
    $this->assertSame(0, $saved);
  }

  /**
   * The explicit development escape is visible and never exits ready.
   */
  public function testDevelopmentEscapeRegistersButReturnsNotReady(): void {
    $saved = 0;
    $storage = $this->registrationStorage($saved);
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->with('mcp_tool_config')->willReturn($storage);

    $invalidator = $this->createMock(CacheTagsInvalidatorInterface::class);
    $invalidator->expects($this->once())->method('invalidateTags');
    $command = $this->command(
      $entityTypeManager,
      $this->moduleHandler([
        'mcp_server_tool_bridge' => TRUE,
        'mcp_server_oauth' => FALSE,
      ]),
      $invalidator,
    );

    $result = $command->setup([
      'allow-unauthenticated-development' => TRUE,
      'require-oauth' => FALSE,
    ]);

    $this->assertSame(3, $result);
    $this->assertSame(count(McpToolScopeResolver::REQUIRED_TOOLS), $saved);
  }

  /**
   * A mid-batch save failure deletes every newly written registration.
   */
  public function testSetupRollsBackPartialWrites(): void {
    $entities = [];
    $deleted = 0;
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('load')->willReturn(NULL);
    $storage->method('create')->willReturnCallback(
      function (array $values) use (&$deleted, &$entities): ConfigEntityInterface {
        $entity = $this->createMock(ConfigEntityInterface::class);
        $entity->method('id')->willReturn($values['id']);
        $entity->method('set')->willReturnSelf();
        $entity->method('setThirdPartySetting')->willReturnSelf();
        $entity->method('getThirdPartySetting')->willReturn(['mcp_read']);
        if (count($entities) === 1) {
          $entity->method('save')->willThrowException(new \RuntimeException('write failed'));
        }
        else {
          $entity->method('save')->willReturn(1);
        }
        if (count($entities) < 2) {
          $entity->expects($this->once())->method('delete')->willReturnCallback(
            static function () use (&$deleted): void {
              $deleted++;
            },
          );
        }
        else {
          $entity->expects($this->never())->method('delete');
        }
        $entities[] = $entity;
        return $entity;
      },
    );
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')->with('mcp_tool_config')->willReturn($storage);

    $command = $this->command(
      $entityTypeManager,
      $this->moduleHandler([
        'mcp_server_tool_bridge' => TRUE,
        'mcp_server_oauth' => TRUE,
      ]),
    );

    $this->assertSame(1, $command->setup());
    $this->assertCount(count(McpToolScopeResolver::REQUIRED_TOOLS), $entities);
    $this->assertSame(2, $deleted);
  }

  /**
   * Agent provisioning owns identity binding but never creates a secret.
   */
  public function testAgentProvisionBindsIdentityAndDesignatesLast(): void {
    $deleted = 0;
    $consumerFields = [];
    $entityTypeManager = $this->agentEntityTypeManager(
      FALSE,
      $deleted,
      $consumerFields,
    );
    $command = $this->command($entityTypeManager, $this->moduleHandler([
      'consumers' => TRUE,
      'simple_oauth' => TRUE,
    ]));

    $result = $command->agentProvision('content', ['env' => 'prod']);

    $this->assertSame(0, $result);
    $this->assertSame(['content-prod'], $this->config('mcp_sentinel.settings')->get('agent_oauth_clients'));
    $this->assertSame(42, $consumerFields['owner_id']);
    $this->assertSame(1, $consumerFields['status']);
    $this->assertSame([
      ['scope_id' => 'mcp_read'],
      ['scope_id' => 'mcp_write'],
    ], $consumerFields['scopes']);
    $this->assertArrayNotHasKey('secret', $consumerFields);
    // d.o #3616862: a provisioned consumer must be able to actually mint
    // tokens — the client_credentials grant enabled and simple_oauth's
    // default user bound to the tier account. Without these the principal
    // satisfies the readiness contract yet fails every token request.
    $this->assertSame([['value' => 'client_credentials']], $consumerFields['grant_types']);
    $this->assertSame(42, $consumerFields['user_id']);
    $this->assertSame(0, $deleted);
  }

  /**
   * A failed Consumer save rolls back all new identity and designation state.
   */
  public function testAgentProvisionRollsBackIdentityBatch(): void {
    $deleted = 0;
    $consumerFields = [];
    $entityTypeManager = $this->agentEntityTypeManager(
      TRUE,
      $deleted,
      $consumerFields,
    );
    $command = $this->command($entityTypeManager, $this->moduleHandler([
      'consumers' => TRUE,
      'simple_oauth' => TRUE,
    ]));

    $result = $command->agentProvision('content', ['env' => 'prod']);

    $this->assertSame(1, $result);
    $this->assertSame([], $this->config('mcp_sentinel.settings')->get('agent_oauth_clients'));
    $this->assertSame(3, $deleted);
  }

  /**
   * Builds a command with deterministic console IO.
   */
  private function command(
    EntityTypeManagerInterface $entityTypeManager,
    ModuleHandlerInterface $moduleHandler,
    ?CacheTagsInvalidatorInterface $invalidator = NULL,
  ): McpSentinelServerCommands {
    $command = new McpSentinelServerCommands(
      $entityTypeManager,
      $moduleHandler,
      $this->container->get('plugin.manager.tool'),
      $invalidator ?? $this->createMock(CacheTagsInvalidatorInterface::class),
      $this->container->get('config.factory'),
    );
    $command->setInput(new ArrayInput([]));
    $command->setOutput(new BufferedOutput());
    return $command;
  }

  /**
   * Builds a module-existence map.
   */
  private function moduleHandler(array $modules): ModuleHandlerInterface {
    $handler = $this->createMock(ModuleHandlerInterface::class);
    $handler->method('moduleExists')->willReturnCallback(
      static fn (string $module): bool => (bool) ($modules[$module] ?? FALSE),
    );
    return $handler;
  }

  /**
   * Builds in-memory registration entities and counts saves.
   */
  private function registrationStorage(int &$saved): EntityStorageInterface {
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('load')->willReturn(NULL);
    $storage->method('create')->willReturnCallback(
      function (array $values) use (&$saved): ConfigEntityInterface {
        $settings = [];
        $entity = $this->createMock(ConfigEntityInterface::class);
        $entity->method('id')->willReturn($values['id']);
        $entity->method('set')->willReturnSelf();
        $entity->method('setThirdPartySetting')->willReturnCallback(
          function (string $provider, string $key, mixed $value) use (&$settings, $entity): ConfigEntityInterface {
            $settings[$provider][$key] = $value;
            return $entity;
          },
        );
        $entity->method('getThirdPartySetting')->willReturnCallback(
          static function (string $provider, string $key) use (&$settings): mixed {
            return $settings[$provider][$key] ?? NULL;
          },
        );
        $entity->method('save')->willReturnCallback(
          static function () use (&$saved): int {
            $saved++;
            return 1;
          },
        );
        return $entity;
      },
    );
    return $storage;
  }

  /**
   * Builds the identity/profile/scope storages used by agent provisioning.
   *
   * @param bool $consumerSaveFails
   *   Whether the Consumer save should fail after role and account writes.
   * @param int $deleted
   *   Receives the number of rollback deletes.
   * @param array<string, mixed> $consumerFields
   *   Receives fields written to the Consumer; secrets must never appear.
   */
  private function agentEntityTypeManager(
    bool $consumerSaveFails,
    int &$deleted,
    array &$consumerFields,
  ): EntityTypeManagerInterface {
    $scopeStorage = $this->createMock(EntityStorageInterface::class);
    $scopeStorage->method('load')->willReturn(
      $this->createMock(ConfigEntityInterface::class),
    );

    $profile = $this->createMock(McpPolicyProfileInterface::class);
    $profile->method('status')->willReturn(TRUE);
    $profile->method('getRoles')->willReturn(['mcp_content_editor']);
    $profileStorage = $this->createMock(EntityStorageInterface::class);
    $profileStorage->method('loadMultiple')->willReturn(['content' => $profile]);

    $role = $this->createMock(RoleInterface::class);
    $role->method('save')->willReturn(1);
    $role->method('delete')->willReturnCallback(
      static function () use (&$deleted): void {
        $deleted++;
      },
    );
    $roleStorage = $this->createMock(EntityStorageInterface::class);
    $roleStorage->method('load')->willReturn(NULL);
    $roleStorage->method('create')->willReturn($role);

    $account = $this->createMock(UserInterface::class);
    $account->method('id')->willReturn(42);
    $account->method('addRole')->willReturnSelf();
    $account->method('save')->willReturn(1);
    $account->method('delete')->willReturnCallback(
      static function () use (&$deleted): void {
        $deleted++;
      },
    );
    $userStorage = $this->createMock(EntityStorageInterface::class);
    $userStorage->method('loadByProperties')->willReturn([]);
    $userStorage->method('create')->willReturn($account);

    $consumer = $this->createMock(ContentEntityInterface::class);
    $consumer->method('set')->willReturnCallback(
      static function (string $field, mixed $value) use (&$consumerFields, $consumer): ContentEntityInterface {
        $consumerFields[$field] = $value;
        return $consumer;
      },
    );
    $consumer->method('hasField')->with('scopes')->willReturn(TRUE);
    if ($consumerSaveFails) {
      $consumer->method('save')->willThrowException(new \RuntimeException('consumer write failed'));
    }
    else {
      $consumer->method('save')->willReturn(1);
    }
    $consumer->method('delete')->willReturnCallback(
      static function () use (&$deleted): void {
        $deleted++;
      },
    );
    $consumerStorage = $this->createMock(EntityStorageInterface::class);
    $consumerStorage->method('loadByProperties')->willReturn([]);
    $consumerStorage->method('create')->willReturn($consumer);

    $storages = [
      'oauth2_scope' => $scopeStorage,
      'mcp_policy_profile' => $profileStorage,
      'user_role' => $roleStorage,
      'user' => $userStorage,
      'consumer' => $consumerStorage,
    ];
    $manager = $this->createMock(EntityTypeManagerInterface::class);
    $manager->method('getStorage')->willReturnCallback(
      static fn (string $type): EntityStorageInterface => $storages[$type],
    );
    return $manager;
  }

  /**
   * Reconcile provisions every declared tier.
   */
  public function testAgentReconcileProvisionsDeclaredTiers(): void {
    $this->config('mcp_sentinel.settings')
      ->set('agent_provision_tiers', ['content:prod'])
      ->save();
    $deleted = 0;
    $consumerFields = [];
    $command = $this->command(
      $this->agentEntityTypeManager(FALSE, $deleted, $consumerFields),
      $this->moduleHandler(['consumers' => TRUE, 'simple_oauth' => TRUE]),
    );

    $result = $command->agentReconcile();

    $this->assertSame(0, $result);
    $this->assertSame(['content-prod'], $this->config('mcp_sentinel.settings')->get('agent_oauth_clients'));
    $this->assertSame([['value' => 'client_credentials']], $consumerFields['grant_types']);
  }

  /**
   * An invalid declared entry fails the run but valid entries still provision.
   */
  public function testAgentReconcileSkipsInvalidEntriesAndFails(): void {
    $this->config('mcp_sentinel.settings')
      ->set('agent_provision_tiers', ['bogus:prod', 'content:prod'])
      ->save();
    $deleted = 0;
    $consumerFields = [];
    $command = $this->command(
      $this->agentEntityTypeManager(FALSE, $deleted, $consumerFields),
      $this->moduleHandler(['consumers' => TRUE, 'simple_oauth' => TRUE]),
    );

    $result = $command->agentReconcile();

    $this->assertNotSame(0, $result,
      'A declared principal that cannot be reconciled must fail the run, not vanish silently.');
    $this->assertSame(['content-prod'], $this->config('mcp_sentinel.settings')->get('agent_oauth_clients'),
      'Valid declarations still provision.');
  }

  /**
   * No declaration means an honest no-op.
   */
  public function testAgentReconcileNoDeclarationIsNoop(): void {
    $deleted = 0;
    $consumerFields = [];
    $command = $this->command(
      $this->agentEntityTypeManager(FALSE, $deleted, $consumerFields),
      $this->moduleHandler(['consumers' => TRUE, 'simple_oauth' => TRUE]),
    );

    $result = $command->agentReconcile();

    $this->assertSame(0, $result);
    $this->assertSame([], $consumerFields, 'No writes when nothing is declared.');
  }

}
