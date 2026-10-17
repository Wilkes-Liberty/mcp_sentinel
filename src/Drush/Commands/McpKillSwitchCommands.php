<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountSwitcherInterface;
use Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorBinding;
use Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillSwitchResult;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\user\UserInterface;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Operator commands for the agent kill switch (DEV-986).
 *
 * No UI in this slice. Permission: administer agent kill switch.
 *
 * Every command requires a Paladin access token (PALADIN_TOKEN or
 * stdin, never --token) and --operator=<Drupal account name>. The
 * token is introspected at Paladin: active, future exp, pinned iss
 * and aud, pinned operator audience or role, and no act or actor
 * claim. Identity is paladin:iss|sub from that response. The token
 * is mapped to a Drupal account through operator binding.
 * --operator must be that account. The command then switches to
 * that account for the permission check and switches back in
 * finally. Anonymous stays refused. Paladin down fails closed.
 * The two-person rule compares iss|sub and mapped Drupal uids, not
 * the OS user. The OS-user HMAC is off unless settings.php enables
 * it. Bind maps the token to --operator. Binding a second identity
 * onto an already-bound record is refused.
 */
final class McpKillSwitchCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * PHPUnit-only: skip --operator matching the mapped account.
   */
  public const WEAKEN_SKIP_OPERATOR_MATCH = 'skip_operator_match';

  /**
   * Test-only weaken flags. Empty in production.
   *
   * @var array<string, true>
   */
  private array $weakenForTest = [];

  /**
   * Constructs the command file.
   *
   * @param \Drupal\mcp_sentinel\Service\McpKillSwitch $killSwitch
   *   Kill registry.
   * @param \Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory $operatorIdentities
   *   Paladin token identity resolver.
   * @param \Drupal\mcp_sentinel\Service\McpOperatorBinding $operatorBindings
   *   Paladin-to-Drupal-account bindings.
   * @param \Drupal\mcp_sentinel\Service\McpWebhookQueueManager $webhookQueue
   *   Held webhook deliveries.
   * @param \Drupal\Core\Session\AccountSwitcherInterface $accountSwitcher
   *   Switches to the mapped operator for the permission check.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   User storage for --operator and mapped uids.
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   Correlation ids for release and discard.
   */
  public function __construct(
    #[Autowire(service: 'mcp_sentinel.kill_switch')]
    private readonly McpKillSwitch $killSwitch,
    #[Autowire(service: 'mcp_sentinel.operator_identity')]
    private readonly McpOperatorIdentityFactory $operatorIdentities,
    #[Autowire(service: 'mcp_sentinel.operator_binding')]
    private readonly McpOperatorBinding $operatorBindings,
    #[Autowire(service: 'mcp_sentinel.webhook_queue_manager')]
    private readonly McpWebhookQueueManager $webhookQueue,
    #[Autowire(service: 'account_switcher')]
    private readonly AccountSwitcherInterface $accountSwitcher,
    #[Autowire(service: 'entity_type.manager')]
    private readonly EntityTypeManagerInterface $entityTypeManager,
    #[Autowire(service: 'uuid')]
    private readonly UuidInterface $uuid,
  ) {
    parent::__construct();
  }

  /**
   * Kill one principal, every agent of this person, a tenant, or a mass set.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill', aliases: ['mcps:kill'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor. Repeat for a mass kill.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub: every agent of this person (mass).')]
  #[CLI\Option(name: 'tenant', description: 'Tenant-wide selector (mass).')]
  #[CLI\Option(name: 'reason', description: 'Operator reason. Required. No tokens.')]
  #[CLI\Option(name: 'ttl', description: 'Lifetime in seconds. Default 86400, max 604800.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill --operator=alice --principal-key=iss|sub|actor --reason="compromise"', description: 'Kill one principal immediately.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill --operator=alice --human-key=iss|sub --reason="mass revoke"', description: 'Person-wide freeze. In-scope agents are refused immediately; a second operator confirms, extends, or lifts.')]
  public function kill(
    array $options = [
      'principal-key' => [],
      'human-key' => [],
      'tenant' => [],
      'reason' => '',
      'ttl' => NULL,
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($options): int {
      $ttlRaw = $options['ttl'] ?? '';
      $ttl = $ttlRaw === '' ? NULL : (int) $ttlRaw;
      $result = $this->killSwitch->kill(
        $this->selectorsFromOptions($options),
        (string) $options['reason'],
        $identity,
        $ttl,
      );
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Second operator confirms a mass freeze (keeps it).
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-confirm', aliases: ['mcps:kill-confirm'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-confirm BATCH --operator=bob', description: 'Confirm a mass freeze as a distinct operator.')]
  public function confirmKill(
    string $batch,
    array $options = [
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($batch): int {
      $result = $this->killSwitch->confirm($batch, $identity);
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Second operator extends a mass freeze (7-day cap).
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-extend', aliases: ['mcps:kill-extend'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Option(name: 'ttl', description: 'Lifetime in seconds from now. Default 86400, max 604800.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-extend BATCH --operator=bob --ttl=604800', description: 'Extend a mass freeze as a distinct operator.')]
  public function extendKill(
    string $batch,
    array $options = [
      'ttl' => NULL,
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($batch, $options): int {
      $ttlRaw = $options['ttl'] ?? '';
      $ttl = $ttlRaw === '' ? NULL : (int) $ttlRaw;
      $result = $this->killSwitch->extend($batch, $identity, $ttl);
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Second operator lifts an unconfirmed mass freeze.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-lift', aliases: ['mcps:kill-lift'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-lift BATCH --operator=bob', description: 'Lift an unconfirmed mass freeze. Held deliveries stay held.')]
  public function liftKill(
    string $batch,
    array $options = [
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($batch): int {
      $result = $this->killSwitch->lift($batch, $identity);
      $this->printResult($result);
      $this->output()->writeln('held_items: unchanged (release or discard explicitly)');
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Break-glass keep, extend, or lift when the second person is unreachable.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-break-glass', aliases: ['mcps:kill-break-glass'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Option(name: 'keep', description: 'Confirm (keep) the freeze.')]
  #[CLI\Option(name: 'extend', description: 'Extend the freeze. Pass seconds with --ttl.')]
  #[CLI\Option(name: 'lift', description: 'Lift the freeze. Held deliveries stay held.')]
  #[CLI\Option(name: 'ttl', description: 'Lifetime in seconds when extending. Default 86400, max 604800.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-break-glass BATCH --operator=breakglass-op --keep', description: 'Break-glass keep of a mass freeze.')]
  public function breakGlassKill(
    string $batch,
    array $options = [
      'keep' => FALSE,
      'extend' => FALSE,
      'lift' => FALSE,
      'ttl' => NULL,
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($batch, $options): int {
      $action = $this->breakGlassAction($options);
      $ttlRaw = $options['ttl'] ?? '';
      $ttl = $ttlRaw === '' ? NULL : (int) $ttlRaw;
      $result = $this->killSwitch->breakGlass(
        $batch,
        $action,
        $identity,
        $ttl,
      );
      $this->printResult($result);
      $this->output()->writeln('break_glass: ' . $action->value);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * List held webhook deliveries.
   */
  #[CLI\Command(name: 'mcp-sentinel:webhook-held', aliases: ['mcps:webhook-held'])]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:webhook-held --operator=alice', description: 'List webhook deliveries held by a kill.')]
  public function listHeld(
    array $options = [
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (): int {
      $rows = $this->webhookQueue->listHeld();
      if ($rows === []) {
        $this->output()->writeln('held: none');
        return self::EXIT_SUCCESS;
      }
      $table = [];
      foreach ($rows as $row) {
        $table[] = [
          (string) $row['id'],
          (string) ($row['endpoint_id'] ?? ''),
          (string) ($row['event_name'] ?? ''),
          (string) ($row['principal_key'] ?? ''),
          (string) ($row['human_key'] ?? ''),
          (string) ($row['tenant'] ?? ''),
        ];
      }
      $this->io()->table(
        ['id', 'endpoint', 'event', 'principal_key', 'human_key', 'tenant'],
        $table,
      );
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Release held webhook deliveries so they deliver as originally queued.
   */
  #[CLI\Command(name: 'mcp-sentinel:webhook-release', aliases: ['mcps:webhook-release'])]
  #[CLI\Option(name: 'id', description: 'Held delivery id. Repeat for a batch.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:webhook-release --operator=alice --id=12 --id=13', description: 'Release held deliveries. Same payload, id, and body signature.')]
  public function releaseHeld(
    array $options = [
      'id' => [],
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($options): int {
      $ids = $this->idList($options['id'] ?? []);
      $correlationId = $this->uuid->generate();
      $released = $this->webhookQueue->releaseHeld($ids, $identity, $correlationId);
      $this->output()->writeln('released: ' . implode(',', $released));
      $this->output()->writeln('correlation_id: ' . $correlationId);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Discard held webhook deliveries. They are never delivered.
   */
  #[CLI\Command(name: 'mcp-sentinel:webhook-discard', aliases: ['mcps:webhook-discard'])]
  #[CLI\Option(name: 'id', description: 'Held delivery id. Repeat for a batch.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:webhook-discard --operator=alice --id=12', description: 'Discard held deliveries. They are never sent.')]
  public function discardHeld(
    array $options = [
      'id' => [],
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($options): int {
      $ids = $this->idList($options['id'] ?? []);
      $correlationId = $this->uuid->generate();
      $discarded = $this->webhookQueue->discardHeld($ids, $identity, $correlationId);
      $this->output()->writeln('discarded: ' . implode(',', $discarded));
      $this->output()->writeln('correlation_id: ' . $correlationId);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Request an un-kill. Always needs a distinct second operator.
   */
  #[CLI\Command(name: 'mcp-sentinel:unkill', aliases: ['mcps:unkill'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub.')]
  #[CLI\Option(name: 'tenant', description: 'Tenant selector.')]
  #[CLI\Option(name: 'reason', description: 'Operator reason. Required. No tokens.')]
  #[CLI\Option(name: 'confirm-batch', description: 'Batch id from an un-kill request, to confirm as the named second person (secondary account holder).')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:unkill --operator=alice --principal-key=iss|sub|actor --reason="restored"', description: 'Request an un-kill (pending confirm).')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:unkill --operator=bob --confirm-batch=BATCH', description: 'Confirm an un-kill as a distinct operator.')]
  public function unkill(
    array $options = [
      'principal-key' => [],
      'human-key' => [],
      'tenant' => [],
      'reason' => '',
      'confirm-batch' => NULL,
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($options): int {
      $confirmBatch = trim((string) ($options['confirm-batch'] ?? ''));
      if ($confirmBatch !== '') {
        $result = $this->killSwitch->confirmUnkill($confirmBatch, $identity);
        $this->printResult($result);
        return self::EXIT_SUCCESS;
      }
      $result = $this->killSwitch->requestUnkill(
        $this->selectorsFromOptions($options),
        (string) $options['reason'],
        $identity,
      );
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Bind this Paladin token to the Drupal account in --operator.
   *
   * The iss|sub is taken from an active Paladin introspection
   * response, never from --human-key. Paladin unreachable fails
   * closed. A second identity on an already-bound record is
   * refused. Pipe the token on stdin or set PALADIN_TOKEN; --token
   * is refused. --operator is the Drupal account this token maps
   * to. If the token is already bound, --operator must match that
   * account.
   */
  #[CLI\Command(name: 'mcp-sentinel:operator-bind', aliases: ['mcps:operator-bind'])]
  #[CLI\Option(name: 'operator', description: 'Drupal account name to bind this Paladin token to.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:operator-bind --operator=alice', description: 'Bind this Paladin iss|sub to the alice account.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:operator-bind --operator=alice < token.txt', description: 'Bind using a token piped on stdin.')]
  public function bindOperator(
    array $options = [
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsNamedOperator($options, function (McpOperatorIdentity $identity, UserInterface $account): int {
      $mappedUid = $this->operatorBindings->uidFor($identity);
      if ($mappedUid > 0 && $mappedUid !== (int) $account->id()
        && !$this->weakened(self::WEAKEN_SKIP_OPERATOR_MATCH)) {
        throw new McpKillSwitchException(
          McpKillSwitchException::OPERATOR_MISMATCH,
          '--operator must be the Drupal account bound to this Paladin token.',
        );
      }
      $operatorId = $this->operatorBindings->bindToAccount(
        $identity,
        (int) $account->id(),
      );
      $this->output()->writeln('operator_id: ' . $operatorId);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Unbind an operator record. Two distinct Paladin operators required.
   */
  #[CLI\Command(name: 'mcp-sentinel:operator-unbind', aliases: ['mcps:operator-unbind'])]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Option(name: 'confirm-batch', description: 'Batch id from an unbind request, to confirm as the named second person (secondary account holder).')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:operator-unbind --operator=alice', description: 'Request unbind of this Paladin operator record (pending confirm).')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:operator-unbind --operator=bob --confirm-batch=BATCH', description: 'Confirm an unbind as a distinct operator.')]
  public function unbindOperator(
    array $options = [
      'operator' => '',
      'token' => '',
      'confirm-batch' => NULL,
    ],
  ): int {
    return $this->runAsBoundOperator($options, function (McpOperatorIdentity $identity) use ($options): int {
      $confirmBatch = trim((string) ($options['confirm-batch'] ?? ''));
      if ($confirmBatch !== '') {
        $this->operatorBindings->confirmUnbind($confirmBatch, $identity);
        $this->output()->writeln('status: unbound');
        return self::EXIT_SUCCESS;
      }
      $batchId = $this->operatorBindings->requestUnbind($identity);
      $this->output()->writeln('status: unbind_pending');
      $this->output()->writeln('batch: ' . $batchId);
      $this->output()->writeln(
        'needs_confirm: yes (named second person / secondary account holder)',
      );
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Show kill-block status for a selector.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-status', aliases: ['mcps:kill-status'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub.')]
  #[CLI\Option(name: 'tenant', description: 'Tenant selector.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-status --operator=alice --principal-key=iss|sub|actor', description: 'Print the kill-block row for one principal.')]
  public function status(
    array $options = [
      'principal-key' => [],
      'human-key' => [],
      'tenant' => [],
      'operator' => '',
      'token' => '',
    ],
  ): int {
    return $this->runAsBoundOperator($options, function () use ($options): int {
      $selectors = $this->selectorsFromOptions($options);
      if (count($selectors) !== 1) {
        $this->logger()->error('kill-status requires exactly one selector.');
        return self::EXIT_FAILURE;
      }
      $row = $this->killSwitch->status($selectors[0]);
      if ($row === NULL) {
        $this->output()->writeln('status: active');
        return self::EXIT_SUCCESS;
      }
      foreach ([
        'status' => (string) $row['status'],
        'selector_type' => (string) $row['selector_type'],
        'selector_key' => (string) $row['selector_key'],
        'block_until' => (string) $row['block_until'],
        'ttl' => (string) $row['ttl'],
        'batch_id' => (string) $row['batch_id'],
        'requested_by' => (string) $row['requested_by'],
        'confirmed_by' => (string) $row['confirmed_by'],
        'unkill_batch_id' => (string) $row['unkill_batch_id'],
      ] as $field => $value) {
        $this->output()->writeln($field . ': ' . $value);
      }
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * PHPUnit-only injection that disables --operator matching.
   *
   * @param string $flag
   *   One of the WEAKEN_* constants.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function weakenForTest(string $flag): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Kill-switch command weaken flags can be set only under PHPUnit.',
      );
    }
    $this->weakenForTest[$flag] = TRUE;
  }

  /**
   * Builds selectors from repeated Drush options.
   *
   * @param array<string, mixed> $options
   *   Command options.
   *
   * @return list<\Drupal\mcp_sentinel\Value\McpKillSelector>
   *   Selectors.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   */
  private function selectorsFromOptions(array $options): array {
    $selectors = [];
    foreach ($this->optionList($options['principal-key'] ?? []) as $key) {
      $selectors[] = McpKillSelector::principalKey($key);
    }
    foreach ($this->optionList($options['human-key'] ?? []) as $key) {
      $selectors[] = McpKillSelector::humanKey($key);
    }
    foreach ($this->optionList($options['tenant'] ?? []) as $key) {
      $selectors[] = McpKillSelector::tenant($key);
    }
    return $selectors;
  }

  /**
   * Normalizes a Drush option that may be a string or a list.
   *
   * @param mixed $value
   *   Option value.
   *
   * @return list<string>
   *   Non-empty strings.
   */
  private function optionList(mixed $value): array {
    if ($value === NULL || $value === '' || $value === []) {
      return [];
    }
    if (!is_array($value)) {
      $value = [$value];
    }
    $out = [];
    foreach ($value as $item) {
      $item = trim((string) $item);
      if ($item !== '') {
        $out[] = $item;
      }
    }
    return $out;
  }

  /**
   * Prints a compact operator-facing result.
   */
  private function printResult(McpKillSwitchResult $result): void {
    $this->output()->writeln('status: ' . $result->status->value);
    $this->output()->writeln('batch: ' . $result->batchId);
    if ($result->needsConfirm) {
      $this->output()->writeln(
        'needs_confirm: yes (named second person / secondary account holder).',
      );
      $this->output()->writeln(
        'freeze: in force now. Unconfirmed timeout keeps it and escalates.',
      );
    }
    if ($result->blockUntil > 0) {
      $this->output()->writeln('block_until: ' . (string) $result->blockUntil);
    }
    $this->output()->writeln('ttl: ' . (string) $result->ttl);
  }

  /**
   * Paladin access token from PALADIN_TOKEN or stdin. Never logged.
   *
   * --token is refused: it lands in shell history and in ps. An empty
   * value is passed through so bind and unbind can audit the refusal.
   *
   * @param array<string, mixed> $options
   *   Command options.
   *
   * @return string
   *   Access token, or empty when neither source provided one.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When --token is passed.
   */
  private function paladinToken(array $options): string {
    if (trim((string) ($options['token'] ?? '')) !== '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'Do not pass --token. Pipe the token on stdin or set PALADIN_TOKEN.',
      );
    }
    $fromEnv = getenv('PALADIN_TOKEN');
    if (is_string($fromEnv) && trim($fromEnv) !== '') {
      return trim($fromEnv);
    }
    if (!defined('STDIN') || (function_exists('posix_isatty') && posix_isatty(STDIN))) {
      return '';
    }
    $fromStdin = stream_get_contents(STDIN);
    return is_string($fromStdin) ? trim($fromStdin) : '';
  }

  /**
   * Token plus mapped --operator, then switchTo for the permission check.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param callable(\Drupal\mcp_sentinel\Value\McpOperatorIdentity): int $callback
   *   Work to run as the mapped operator.
   */
  private function runAsBoundOperator(array $options, callable $callback): int {
    return $this->withOperatorSwitch($options, function (McpOperatorIdentity $identity) use ($options, $callback): int {
      $account = $this->mappedAccount($identity);
      $this->assertOperatorOption($options, $account);
      return $this->switchAndRun($account, $identity, $callback);
    });
  }

  /**
   * Token plus --operator account name. Used by bind before a mapping exists.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param callable(\Drupal\mcp_sentinel\Value\McpOperatorIdentity, \Drupal\user\UserInterface): int $callback
   *   Work to run as the named operator.
   */
  private function runAsNamedOperator(array $options, callable $callback): int {
    return $this->withOperatorSwitch($options, function (McpOperatorIdentity $identity) use ($options, $callback): int {
      $account = $this->accountFromOperatorOption($options);
      return $this->switchAndRun($account, $identity, static function (McpOperatorIdentity $bound) use ($callback, $account): int {
        return $callback($bound, $account);
      });
    });
  }

  /**
   * Reads and verifies the token, then runs the callback.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param callable(\Drupal\mcp_sentinel\Value\McpOperatorIdentity): int $callback
   *   Work after the token is verified.
   */
  private function withOperatorSwitch(array $options, callable $callback): int {
    try {
      $token = $this->paladinToken($options);
      $identity = $this->operatorIdentities->forDrushCommand($token);
      return $callback($identity);
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->reasonCode . ': ' . $e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Switch to the mapped account, check permission, then switch back.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal account bound to the Paladin token.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $identity
   *   Verified Paladin operator identity.
   * @param callable(\Drupal\mcp_sentinel\Value\McpOperatorIdentity): int $callback
   *   Work to run as $account.
   */
  private function switchAndRun(UserInterface $account, McpOperatorIdentity $identity, callable $callback): int {
    $this->accountSwitcher->switchTo($account);
    try {
      $this->killSwitch->assertOperatorAccess($account);
      return $callback($identity);
    }
    finally {
      $this->accountSwitcher->switchBack();
    }
  }

  /**
   * Drupal account bound to this Paladin identity.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function mappedAccount(McpOperatorIdentity $identity): UserInterface {
    $uid = $this->operatorBindings->uidFor($identity);
    if ($uid <= 0) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'This Paladin identity is not bound to a Drupal operator account.',
      );
    }
    $account = $this->entityTypeManager->getStorage('user')->load($uid);
    if (!$account instanceof UserInterface || (int) $account->id() === 0) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'This Paladin identity is not bound to a Drupal operator account.',
      );
    }
    return $account;
  }

  /**
   * Drupal account named by --operator.
   *
   * @param array<string, mixed> $options
   *   Command options.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function accountFromOperatorOption(array $options): UserInterface {
    $name = trim((string) ($options['operator'] ?? ''));
    if ($name === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::OPERATOR_MISMATCH,
        '--operator must be the Drupal account bound to this Paladin token.',
      );
    }
    $accounts = $this->entityTypeManager->getStorage('user')->loadByProperties([
      'name' => $name,
    ]);
    $account = reset($accounts);
    if (!$account instanceof UserInterface || (int) $account->id() === 0) {
      throw new McpKillSwitchException(
        McpKillSwitchException::OPERATOR_MISMATCH,
        '--operator must be the Drupal account bound to this Paladin token.',
      );
    }
    return $account;
  }

  /**
   * The --operator option must equal the mapped Drupal account name.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param \Drupal\user\UserInterface $account
   *   Drupal account bound to the Paladin token.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertOperatorOption(array $options, UserInterface $account): void {
    if ($this->weakened(self::WEAKEN_SKIP_OPERATOR_MATCH)) {
      return;
    }
    $name = trim((string) ($options['operator'] ?? ''));
    $expected = $account->getAccountName();
    if ($name === '' || strlen($name) !== strlen($expected) || !hash_equals($expected, $name)) {
      throw new McpKillSwitchException(
        McpKillSwitchException::OPERATOR_MISMATCH,
        '--operator must be the Drupal account bound to this Paladin token.',
      );
    }
  }

  /**
   * Whether a PHPUnit weaken flag is on.
   */
  private function weakened(string $flag): bool {
    return isset($this->weakenForTest[$flag]);
  }

  /**
   * Break-glass action from mutually exclusive flags.
   *
   * @param array<string, mixed> $options
   *   Command options.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function breakGlassAction(array $options): McpKillBreakGlassAction {
    $keep = !empty($options['keep']);
    $extend = !empty($options['extend']);
    $lift = !empty($options['lift']);
    $chosen = (int) $keep + (int) $extend + (int) $lift;
    if ($chosen !== 1) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_ACTION,
        'Pass exactly one of --keep, --extend, or --lift.',
      );
    }
    if ($keep) {
      return McpKillBreakGlassAction::Keep;
    }
    if ($extend) {
      return McpKillBreakGlassAction::Extend;
    }
    return McpKillBreakGlassAction::Lift;
  }

  /**
   * Positive delivery ids from a repeated Drush option.
   *
   * @param mixed $value
   *   Option value.
   *
   * @return list<int>
   *   Ids.
   */
  private function idList(mixed $value): array {
    $ids = [];
    foreach ($this->optionList($value) as $item) {
      $id = (int) $item;
      if ($id > 0) {
        $ids[] = $id;
      }
    }
    return $ids;
  }

}
