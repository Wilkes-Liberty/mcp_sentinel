<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Drush\Commands\McpKillSwitchCommands;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorBinding;
use Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory;
use Drupal\mcp_sentinel\Service\McpPaladinIntrospection;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\User;
use Drush\Log\DrushLoggerManager;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request as GuzzleRequest;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Log\AbstractLogger;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * Drush kill-switch commands require a Paladin token and --operator (DEV-986).
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Drush\Commands\McpKillSwitchCommands
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpKillSwitchCommands::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpKillSwitchCommandsTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;

  /**
   * Synthetic issuer. Not a live IdP.
   */
  private const ISS = 'https://idp.example/realms/agents';

  /**
   * Pinned bind audience.
   */
  private const AUDIENCE = 'mcp-sentinel-operator-bind';

  /**
   * Pinned operator audience.
   */
  private const OPERATOR_AUDIENCE = 'mcp-sentinel-operator';

  /**
   * Distinctive token used to prove it never leaks.
   */
  private const TOKEN = 'tok_REDACT_ME_9f3c1a';

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
   * Command under test.
   */
  private McpKillSwitchCommands $commands;

  /**
   * Captured command output.
   */
  private BufferedOutput $output;

  /**
   * Captured logger records.
   *
   * @var array<int, array{0: string, 1: string}>
   */
  private array $logRecords = [];

  /**
   * Permitted operator alice.
   */
  private User $alice;

  /**
   * Permitted operator bob.
   */
  private User $bob;

  /**
   * Account without the kill-switch permission.
   */
  private User $viewer;

  /**
   * PHPUnit weaken flags reapplied after Paladin service rebuilds.
   *
   * @var list<string>
   */
  private array $introspectionWeaken = [];

  /**
   * PHPUnit weaken flags reapplied after the command is rebuilt.
   *
   * @var list<string>
   */
  private array $commandWeaken = [];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installEntitySchema('user');
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_webhook_delivery']);
    $this->installConfig(['system', 'user', 'mcp_sentinel']);
    $this->setSetting(
      'mcp_sentinel.kill_switch.break_glass_operator',
      self::ISS . '|operator-b',
    );

    $alice = $this->createUser([McpKillSwitch::PERMISSION], 'alice');
    $bob = $this->createUser([McpKillSwitch::PERMISSION], 'bob');
    $viewer = $this->createUser([], 'viewer');
    $this->assertInstanceOf(User::class, $alice);
    $this->assertInstanceOf(User::class, $bob);
    $this->assertInstanceOf(User::class, $viewer);
    $this->alice = $alice;
    $this->bob = $bob;
    $this->viewer = $viewer;
    $this->container->get('current_user')->setAccount(new AnonymousUserSession());

    $this->commands = new McpKillSwitchCommands(
      $this->container->get('mcp_sentinel.kill_switch'),
      $this->container->get('mcp_sentinel.operator_identity'),
      $this->container->get('mcp_sentinel.operator_binding'),
      $this->container->get('mcp_sentinel.webhook_queue_manager'),
      $this->container->get('account_switcher'),
      $this->container->get('entity_type.manager'),
      $this->container->get('uuid'),
    );
    $this->wireIo();
  }

  /**
   * Anonymous with no token is refused for kill and kill-status.
   *
   * @covers ::kill
   * @covers ::status
   */
  public function testAnonymousWithoutTokenFailsForKillAndStatus(): void {
    $kill = $this->commands->kill($this->killOptions());
    $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $kill);
    $this->assertStringContainsString(McpKillSwitchException::UNVERIFIED_OPERATOR, $this->logText());
    $this->assertSame(0, (int) $this->container->get('current_user')->id());

    $this->clearLog();
    $status = $this->commands->status($this->statusOptions());
    $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $status);
    $this->assertStringContainsString(McpKillSwitchException::UNVERIFIED_OPERATOR, $this->logText());
    $this->assertSame(0, (int) $this->container->get('current_user')->id());
  }

  /**
   * A valid token and mapped account can kill; user is anonymous after.
   *
   * @covers ::kill
   */
  public function testValidTokenAndMappedAccountSucceedsThenRestoresAnonymous(): void {
    $this->bindAlice();
    $this->queueActiveTokens(['operator-a']);
    $code = $this->withToken(self::TOKEN, function (): int {
      return $this->commands->kill($this->killOptions([
        'operator' => 'alice',
        'principal-key' => [self::ISS . '|subject-a|agent-a'],
        'reason' => 'compromise',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $code, $this->logText());
    $this->assertStringContainsString('status: killed', $this->output->fetch());
    $this->assertSame(0, (int) $this->container->get('current_user')->id());
    $this->assertStringNotContainsString(self::TOKEN, $this->logText());
    $this->assertStringNotContainsString(self::TOKEN, $this->lastAuditJson());
  }

  /**
   * A mapped account without the permission is PERMISSION_DENIED.
   *
   * @covers ::kill
   */
  public function testMappedAccountWithoutPermissionIsDenied(): void {
    $this->bindings()->bindToAccount($this->paladinA(), (int) $this->viewer->id());
    $this->queueActiveTokens(['operator-a']);
    $code = $this->withToken(self::TOKEN, function (): int {
      return $this->commands->kill($this->killOptions([
        'operator' => 'viewer',
        'principal-key' => [self::ISS . '|subject-a|agent-a'],
        'reason' => 'compromise',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $code);
    $this->assertStringContainsString(McpKillSwitchException::PERMISSION_DENIED, $this->logText());
    $this->assertSame(0, (int) $this->container->get('current_user')->id());
  }

  /**
   * An --operator that does not match the token is OPERATOR_MISMATCH.
   *
   * @covers ::kill
   */
  public function testOperatorOptionMismatchIsRefused(): void {
    $this->bindAlice();
    $this->queueActiveTokens(['operator-a']);
    $code = $this->withToken(self::TOKEN, function (): int {
      return $this->commands->kill($this->killOptions([
        'operator' => 'bob',
        'principal-key' => [self::ISS . '|subject-a|agent-a'],
        'reason' => 'compromise',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $code);
    $this->assertStringContainsString(McpKillSwitchException::OPERATOR_MISMATCH, $this->logText());
  }

  /**
   * Guard bypass: a mismatched --operator runs when the match check is off.
   *
   * @covers ::weakenForTest
   */
  public function testOperatorMismatchSucceedsWhenMatchCheckIsWeakened(): void {
    $this->commandWeaken = [McpKillSwitchCommands::WEAKEN_SKIP_OPERATOR_MATCH];
    $this->bindAlice();
    $this->queueActiveTokens(['operator-a']);
    $code = $this->withToken(self::TOKEN, function (): int {
      return $this->commands->kill($this->killOptions([
        'operator' => 'bob',
        'principal-key' => [self::ISS . '|subject-a|agent-a'],
        'reason' => 'compromise',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $code, $this->logText());
  }

  /**
   * Same OS uid with two tokens can confirm a kill and an un-kill.
   *
   * @covers ::kill
   * @covers ::confirmKill
   * @covers ::unkill
   */
  public function testSameOsUidTwoTokensCanConfirmAndUnkill(): void {
    $this->bindAlice();
    $this->bindBob();
    $this->queueActiveTokens([
      'operator-a',
      'operator-b',
      'operator-a',
      'operator-b',
    ]);
    $this->identities()->setProcessIdentityForTest(1001, 'alice');
    $human = self::ISS . '|subject-two-tokens';
    $kill = $this->withToken('token-alice', function () use ($human): int {
      return $this->commands->kill($this->killOptions([
        'operator' => 'alice',
        'human-key' => [$human],
        'reason' => 'mass',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $kill, $this->logText());
    $batch = $this->batchFrom($this->output->fetch());
    $this->identities()->setProcessIdentityForTest(1001, 'bob');
    $confirm = $this->withToken('token-bob', function () use ($batch): int {
      return $this->commands->confirmKill($batch, [
        'operator' => 'bob',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $confirm, $this->logText());
    $this->output->fetch();

    $unkill = $this->withToken('token-alice', function () use ($human): int {
      return $this->commands->unkill($this->killOptions([
        'operator' => 'alice',
        'human-key' => [$human],
        'reason' => 'restore',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $unkill, $this->logText());
    $unkillBatch = $this->batchFrom($this->output->fetch());
    $unkillConfirm = $this->withToken('token-bob', function () use ($unkillBatch): int {
      return $this->commands->unkill($this->killOptions([
        'operator' => 'bob',
        'confirm-batch' => $unkillBatch,
        'reason' => '',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $unkillConfirm, $this->logText());
  }

  /**
   * One token with two OS uids is still the same operator.
   *
   * @covers ::kill
   * @covers ::confirmKill
   */
  public function testOneTokenTwoOsUidsIsSameOperator(): void {
    $this->bindAlice();
    $this->queueActiveTokens(['operator-a', 'operator-a']);
    $human = self::ISS . '|subject-one-token';
    $this->identities()->setProcessIdentityForTest(1001, 'alice');
    $kill = $this->withToken(self::TOKEN, function () use ($human): int {
      return $this->commands->kill($this->killOptions([
        'operator' => 'alice',
        'human-key' => [$human],
        'reason' => 'mass',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $kill, $this->logText());
    $batch = $this->batchFrom($this->output->fetch());
    $this->identities()->setProcessIdentityForTest(1002, 'bob');
    $confirm = $this->withToken(self::TOKEN, function () use ($batch): int {
      return $this->commands->confirmKill($batch, [
        'operator' => 'alice',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $confirm);
    $this->assertStringContainsString(McpKillSwitchException::SAME_OPERATOR, $this->logText());
  }

  /**
   * Introspection failures refuse kill and confirm.
   *
   * @covers ::kill
   * @covers ::confirmKill
   */
  public function testIntrospectionFailuresRefuseKillAndConfirm(): void {
    $this->bindAlice();
    $this->bindBob();
    $human = McpKillSelector::humanKey(self::ISS . '|subject-fail');
    $pending = $this->container->get('mcp_sentinel.kill_switch')->kill(
      [$human],
      'mass',
      $this->paladinA(),
    );

    $cases = [
      'down' => new ConnectException('down', new GuzzleRequest('POST', 'https://idp.example/introspect')),
      'inactive' => new Response(200, ['Content-Type' => 'application/json'], $this->activeJson([
        'active' => FALSE,
      ])),
      'wrong-aud' => new Response(200, ['Content-Type' => 'application/json'], $this->activeJson([
        'aud' => 'other-client',
        'azp' => 'other-client',
        'client_id' => 'other-client',
      ])),
      'act' => new Response(200, ['Content-Type' => 'application/json'], $this->activeJson([
        'act' => ['sub' => 'agent-1'],
      ])),
      'no-exp' => new Response(200, ['Content-Type' => 'application/json'], $this->jsonWithoutExp()),
    ];
    foreach ($cases as $label => $response) {
      $this->stubPaladinIntrospection([$response, $response]);
      $kill = $this->withToken(self::TOKEN, function (): int {
        return $this->commands->kill($this->killOptions([
          'operator' => 'alice',
          'principal-key' => [self::ISS . '|subject-fail|agent-fail'],
          'reason' => 'compromise',
        ]));
      });
      $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $kill, $label . ' kill');
      $this->clearLog();
      $confirm = $this->withToken(self::TOKEN, function () use ($pending): int {
        return $this->commands->confirmKill($pending->batchId, [
          'operator' => 'bob',
          'token' => '',
        ]);
      });
      $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $confirm, $label . ' confirm');
    }
  }

  /**
   * The --token flag is refused and the token never appears in output.
   *
   * @covers ::kill
   */
  public function testTokenFlagIsRefusedAndTokenNeverLeaks(): void {
    $this->bindAlice();
    $code = $this->commands->kill($this->killOptions([
      'operator' => 'alice',
      'principal-key' => [self::ISS . '|subject-a|agent-a'],
      'reason' => 'compromise',
      'token' => self::TOKEN,
    ]));
    $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $code);
    $this->assertStringContainsString(McpKillSwitchException::UNVERIFIED_OPERATOR, $this->logText());
    $this->assertStringContainsString('Do not pass --token', $this->logText());
    $combined = $this->logText() . $this->output->fetch() . $this->allAuditJson();
    $this->assertStringNotContainsString(self::TOKEN, $combined);
  }

  /**
   * The six DEV-985 commands run through runAsBoundOperator.
   *
   * @covers ::extendKill
   * @covers ::liftKill
   * @covers ::breakGlassKill
   * @covers ::listHeld
   * @covers ::releaseHeld
   * @covers ::discardHeld
   */
  public function testNewCommandsThroughBoundOperator(): void {
    $this->bindAlice();
    $this->bindBob();
    $this->queueActiveTokens([
      'operator-a',
      'operator-b',
      'operator-a',
      'operator-b',
      'operator-b',
      'operator-b',
      'operator-b',
      'operator-b',
    ]);
    $human = self::ISS . '|subject-cmd-ext';
    $kill = $this->withToken('token-alice', function () use ($human): int {
      return $this->commands->kill($this->killOptions([
        'operator' => 'alice',
        'human-key' => [$human],
        'reason' => 'mass',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $kill, $this->logText());
    $batch = $this->batchFrom($this->output->fetch());

    $extend = $this->withToken('token-bob', function () use ($batch): int {
      return $this->commands->extendKill($batch, [
        'ttl' => 86400,
        'operator' => 'bob',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $extend, $this->logText());
    $this->assertStringContainsString('block_until:', $this->output->fetch());

    $liftHuman = self::ISS . '|subject-cmd-lift';
    $liftKill = $this->withToken('token-alice', function () use ($liftHuman): int {
      return $this->commands->kill($this->killOptions([
        'operator' => 'alice',
        'human-key' => [$liftHuman],
        'reason' => 'mass-lift',
      ]));
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $liftKill, $this->logText());
    $liftBatch = $this->batchFrom($this->output->fetch());
    $lift = $this->withToken('token-bob', function () use ($liftBatch): int {
      return $this->commands->liftKill($liftBatch, [
        'operator' => 'bob',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $lift, $this->logText());
    $this->assertStringContainsString('held_items: unchanged', $this->output->fetch());

    $bgHuman = self::ISS . '|subject-cmd-bg';
    $bgKill = $this->container->get('mcp_sentinel.kill_switch')->kill(
      [McpKillSelector::humanKey($bgHuman)],
      'bg-cmd',
      $this->paladinA(),
    );
    $bg = $this->withToken('token-bob', function () use ($bgKill): int {
      return $this->commands->breakGlassKill($bgKill->batchId, [
        'keep' => TRUE,
        'extend' => FALSE,
        'lift' => FALSE,
        'ttl' => NULL,
        'operator' => 'bob',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $bg, $this->logText());
    $this->assertStringContainsString('break_glass: keep', $this->output->fetch());

    $heldId = (int) $this->container->get('database')
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => McpWebhookQueueManager::STATUS_HELD,
        'attempts' => 0,
        'created' => 1,
        'principal_key' => '',
        'human_key' => '',
        'tenant' => '',
      ])->execute();
    $list = $this->withToken('token-bob', function (): int {
      return $this->commands->listHeld([
        'operator' => 'bob',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $list, $this->logText());
    $this->assertStringContainsString((string) $heldId, $this->output->fetch());

    $release = $this->withToken('token-bob', function () use ($heldId): int {
      return $this->commands->releaseHeld([
        'id' => [$heldId],
        'operator' => 'bob',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $release, $this->logText());
    $this->assertStringContainsString('released: ' . $heldId, $this->output->fetch());

    $discardId = (int) $this->container->get('database')
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => McpWebhookQueueManager::STATUS_HELD,
        'attempts' => 0,
        'created' => 1,
        'principal_key' => '',
        'human_key' => '',
        'tenant' => '',
      ])->execute();
    $discard = $this->withToken('token-bob', function () use ($discardId): int {
      return $this->commands->discardHeld([
        'id' => [$discardId],
        'operator' => 'bob',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_SUCCESS, $discard, $this->logText());
    $this->assertStringContainsString('discarded: ' . $discardId, $this->output->fetch());
  }

  /**
   * An --operator mismatch on kill-extend is refused and audited.
   *
   * @covers ::extendKill
   */
  public function testExtendOperatorMismatchIsRefusedAndAudited(): void {
    $this->bindAlice();
    $this->bindBob();
    $pending = $this->container->get('mcp_sentinel.kill_switch')->kill(
      [McpKillSelector::humanKey(self::ISS . '|subject-cmd-mismatch')],
      'mismatch',
      $this->paladinA(),
    );
    $this->queueActiveTokens(['operator-a']);
    $code = $this->withToken(self::TOKEN, function () use ($pending): int {
      return $this->commands->extendKill($pending->batchId, [
        'ttl' => NULL,
        'operator' => 'bob',
        'token' => '',
      ]);
    });
    $this->assertSame(McpKillSwitchCommands::EXIT_FAILURE, $code);
    $this->assertStringContainsString(McpKillSwitchException::OPERATOR_MISMATCH, $this->logText());
    $this->assertStringContainsString(
      McpKillSwitchException::OPERATOR_MISMATCH,
      $this->allAuditJson(),
    );
  }

  /**
   * Wires Drush IO and a capturing logger.
   */
  private function wireIo(): void {
    $this->output = new BufferedOutput();
    $this->commands->setOutput($this->output);
    $input = new ArrayInput([]);
    $ref = new \ReflectionClass($this->commands);
    foreach (['input', 'output'] as $name) {
      if ($ref->hasProperty($name)) {
        $prop = $ref->getProperty($name);
        $prop->setAccessible(TRUE);
        $prop->setValue($this->commands, $name === 'input' ? $input : $this->output);
      }
    }
    $this->logRecords = [];
    $test = $this;
    $spy = new class($test) extends AbstractLogger {

      public function __construct(
        private McpKillSwitchCommandsTest $test,
      ) {}

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        $this->test->recordLog((string) $level, (string) $message);
      }

    };
    $logger = new DrushLoggerManager();
    $logger->add('spy', $spy);
    $this->commands->setLogger($logger);
  }

  /**
   * Stores one captured log line.
   */
  public function recordLog(string $level, string $message): void {
    $this->logRecords[] = [$level, $message];
  }

  /**
   * Runs a callback with PALADIN_TOKEN set.
   *
   * @param string $token
   *   Paladin access token placed on PALADIN_TOKEN.
   * @param callable(): int $callback
   *   Command invocation.
   */
  private function withToken(string $token, callable $callback): int {
    $previous = getenv('PALADIN_TOKEN');
    putenv('PALADIN_TOKEN=' . $token);
    try {
      return $callback();
    }
    finally {
      if ($previous === FALSE) {
        putenv('PALADIN_TOKEN');
      }
      else {
        putenv('PALADIN_TOKEN=' . $previous);
      }
    }
  }

  /**
   * Default kill options.
   *
   * @param array<string, mixed> $override
   *   Option replacements.
   *
   * @return array<string, mixed>
   *   Options.
   */
  private function killOptions(array $override = []): array {
    return $override + [
      'principal-key' => [],
      'human-key' => [],
      'tenant' => [],
      'reason' => '',
      'ttl' => NULL,
      'operator' => '',
      'token' => '',
      'confirm-batch' => NULL,
    ];
  }

  /**
   * Default kill-status options.
   *
   * @param array<string, mixed> $override
   *   Option replacements.
   *
   * @return array<string, mixed>
   *   Options.
   */
  private function statusOptions(array $override = []): array {
    return $override + [
      'principal-key' => [self::ISS . '|subject-a|agent-a'],
      'human-key' => [],
      'tenant' => [],
      'operator' => '',
      'token' => '',
    ];
  }

  /**
   * Binds operator-a to alice.
   */
  private function bindAlice(): void {
    $this->bindings()->bindToAccount($this->paladinA(), (int) $this->alice->id());
  }

  /**
   * Binds operator-b to bob.
   */
  private function bindBob(): void {
    $this->bindings()->bindToAccount($this->paladinB(), (int) $this->bob->id());
  }

  /**
   * Queues active introspection responses for the given subjects.
   *
   * @param list<string> $subs
   *   Token subjects.
   */
  private function queueActiveTokens(array $subs): void {
    $responses = [];
    foreach ($subs as $sub) {
      $responses[] = new Response(200, ['Content-Type' => 'application/json'], $this->activeJson([
        'sub' => $sub,
      ]));
    }
    $this->stubPaladinIntrospection($responses);
  }

  /**
   * Configure Paladin introspection against a mock HTTP client.
   *
   * @param array<int, \Psr\Http\Message\ResponseInterface|\Throwable> $responses
   *   Mocked introspection responses or transport errors.
   */
  private function stubPaladinIntrospection(array $responses): void {
    $this->pinPaladinSettings();
    $stack = HandlerStack::create(new MockHandler($responses));
    $client = new Client(['handler' => $stack]);
    $this->container->set('http_client', $client);
    $this->rebuildPaladinServices($client);
  }

  /**
   * Pins Paladin introspection in settings.php.
   */
  private function pinPaladinSettings(): void {
    $values = Settings::getAll();
    $values['mcp_sentinel.paladin.introspection_url'] = 'https://idp.example/introspect';
    $values['mcp_sentinel.paladin.issuer'] = self::ISS;
    $values['mcp_sentinel.paladin.audience'] = self::AUDIENCE;
    $values['mcp_sentinel.paladin.operator_audience'] = self::OPERATOR_AUDIENCE;
    $values['mcp_sentinel.paladin.client_id'] = 'introspect-client';
    $values['mcp_sentinel.paladin.client_secret'] = 'introspect-secret';
    $this->container->set('settings', new Settings($values));
  }

  /**
   * Rebuilds introspection, identity, binding, and the command object.
   */
  private function rebuildPaladinServices(?ClientInterface $client = NULL): void {
    $introspection = new McpPaladinIntrospection(
      $client ?? $this->container->get('http_client'),
      $this->container->get('settings'),
      $this->container->get('datetime.time'),
    );
    foreach ($this->introspectionWeaken as $flag) {
      $introspection->weakenForTest($flag);
    }
    $factory = new McpOperatorIdentityFactory(
      $this->principalContextHolder(),
      $this->container->get('private_key'),
      $this->container->get('settings'),
      $introspection,
    );
    $binding = new McpOperatorBinding(
      $this->container->get('database'),
      $this->container->get('uuid'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('datetime.time'),
      $this->container->get('config.factory'),
      $introspection,
      $factory,
    );
    $this->container->set('mcp_sentinel.paladin_introspection', $introspection);
    $this->container->set('mcp_sentinel.operator_identity', $factory);
    $this->container->set('mcp_sentinel.operator_binding', $binding);
    $this->commands = new McpKillSwitchCommands(
      $this->container->get('mcp_sentinel.kill_switch'),
      $factory,
      $binding,
      $this->container->get('mcp_sentinel.webhook_queue_manager'),
      $this->container->get('account_switcher'),
      $this->container->get('entity_type.manager'),
      $this->container->get('uuid'),
    );
    foreach ($this->commandWeaken as $flag) {
      $this->commands->weakenForTest($flag);
    }
    $this->wireIo();
  }

  /**
   * Active RFC 7662 payload.
   *
   * @param array<string, mixed> $override
   *   Claim overrides.
   */
  private function activeJson(array $override = []): string {
    $payload = $override + [
      'active' => TRUE,
      'iss' => self::ISS,
      'sub' => 'operator-a',
      'aud' => [self::AUDIENCE, self::OPERATOR_AUDIENCE],
      'exp' => $this->container->get('datetime.time')->getRequestTime() + 3600,
    ];
    return json_encode($payload, JSON_THROW_ON_ERROR);
  }

  /**
   * Active payload with exp removed.
   */
  private function jsonWithoutExp(): string {
    $payload = json_decode($this->activeJson(), TRUE);
    $this->assertIsArray($payload);
    unset($payload['exp']);
    return json_encode($payload, JSON_THROW_ON_ERROR);
  }

  /**
   * First verified Paladin operator.
   */
  private function paladinA(): McpOperatorIdentity {
    return McpOperatorIdentity::paladin(self::ISS . '|operator-a');
  }

  /**
   * Second verified Paladin operator.
   */
  private function paladinB(): McpOperatorIdentity {
    return McpOperatorIdentity::paladin(self::ISS . '|operator-b');
  }

  /**
   * Operator-binding store.
   */
  private function bindings(): McpOperatorBinding {
    return $this->container->get('mcp_sentinel.operator_binding');
  }

  /**
   * Identity factory.
   */
  private function identities(): McpOperatorIdentityFactory {
    return $this->container->get('mcp_sentinel.operator_identity');
  }

  /**
   * Captured log text.
   */
  private function logText(): string {
    return implode("\n", array_column($this->logRecords, 1));
  }

  /**
   * Drops captured log records.
   */
  private function clearLog(): void {
    $this->logRecords = [];
  }

  /**
   * Batch id printed by a successful command.
   */
  private function batchFrom(string $output): string {
    if (preg_match_all('/^batch: (.+)$/m', $output, $matches) < 1) {
      $this->fail('No batch id in output: ' . $output);
    }
    return trim((string) end($matches[1]));
  }

  /**
   * Latest kill-switch audit metadata as JSON.
   */
  private function lastAuditJson(): string {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    if (!is_array($row)) {
      return '';
    }
    return (string) $row['metadata'];
  }

  /**
   * All audit metadata concatenated.
   */
  private function allAuditJson(): string {
    $rows = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->execute()
      ->fetchCol();
    return implode("\n", array_map('strval', $rows));
  }

}
