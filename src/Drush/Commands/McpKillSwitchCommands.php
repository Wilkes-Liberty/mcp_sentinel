<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountSwitcherInterface;
use Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
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
 * and aud, pinned operator audience on aud or a role (not azp or
 * client_id), and no act or actor claim. Identity is
 * paladin:iss|sub from that response. The token
 * is mapped to a Drupal account through operator binding.
 * --operator must be that account. The command then switches to
 * that account for the permission check and switches back in
 * finally. Anonymous stays refused. Paladin down fails closed.
 * The two-person rule compares iss|sub and mapped Drupal uids, not
 * the OS user. Bind requires a matching token claim and one uid to
 * one iss|sub. Every command needs a Paladin token, including
 * kill-extend, kill-lift, kill-break-glass, webhook-held,
 * webhook-release, and webhook-discard.
 */
final class McpKillSwitchCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * HMAC audit operation for a refused operator command.
   */
  public const AUDIT_COMMAND_REFUSED = 'operator_command_refused';

  /**
   * Maximum Paladin token length from PALADIN_TOKEN or one stdin line.
   */
  public const TOKEN_MAX_BYTES = 8192;

  /**
   * PHPUnit-only: skip --operator matching the mapped account.
   */
  public const WEAKEN_SKIP_OPERATOR_MATCH = 'skip_operator_match';

  /**
   * PHPUnit-only: leave the switched operator as currentUser.
   */
  public const WEAKEN_SKIP_SWITCH_BACK = 'skip_switch_back';

  /**
   * PHPUnit-only: skip the operator_command_refused audit row.
   */
  public const WEAKEN_SKIP_COMMAND_REFUSAL_AUDIT = 'skip_command_refusal_audit';

  /**
   * PHPUnit-only: skip the administer-agent-kill-switch check.
   */
  public const WEAKEN_SKIP_PERMISSION = 'skip_permission';

  /**
   * PHPUnit-only: skip the stdin / env token size cap.
   */
  public const WEAKEN_SKIP_TOKEN_SIZE = 'skip_token_size';

  /**
   * PHPUnit-only stdin stream. NULL reads STDIN.
   *
   * @var resource|null
   */
  private $stdinForTest = NULL;

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
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   HMAC audit chain writer.
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
    #[Autowire(service: 'mcp_sentinel.audit_logger')]
    private readonly McpAuditLogger $auditLogger,
  ) {
    parent::__construct();
  }

  /**
   * Kill one principal, every agent of this person, a tenant, or a mass set.
   *
   * @param array<string, mixed> $options
   *   Command options.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill', aliases: ['mcps:kill'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor. Repeat for a mass kill.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub: every agent of this person (mass).')]
  #[CLI\Option(name: 'tenant', description: 'Tenant-wide selector (mass).')]
  #[CLI\Option(name: 'reason', description: 'Operator reason. Required. No tokens.')]
  #[CLI\Option(name: 'ttl', description: 'Lifetime in seconds. Default 86400, max 604800.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill --operator=alice --principal-key=\'iss|sub|actor\' --reason="compromise"', description: 'Kill one principal immediately.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill --operator=alice --human-key=\'iss|sub\' --reason="mass revoke"', description: 'Person-wide freeze. In-scope agents are refused immediately; a second operator confirms, extends, or lifts.')]
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
      $result = $this->killSwitch->kill(
        $this->selectorsFromOptions($options),
        $this->optionString($options, 'reason'),
        $identity,
        $this->optionTtl($options),
      );
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Second operator confirms a mass freeze (keeps it).
   *
   * @param string $batch
   *   Batch id printed by mcp-sentinel:kill.
   * @param array<string, mixed> $options
   *   Command options.
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
   *
   * @param string $batch
   *   Batch id printed by mcp-sentinel:kill.
   * @param array<string, mixed> $options
   *   Command options.
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
      $result = $this->killSwitch->extend(
        $batch,
        $identity,
        $this->optionTtl($options),
      );
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * Second operator lifts an unconfirmed mass freeze.
   *
   * @param string $batch
   *   Batch id printed by mcp-sentinel:kill.
   * @param array<string, mixed> $options
   *   Command options.
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
   *
   * @param string $batch
   *   Batch id printed by mcp-sentinel:kill.
   * @param array<string, mixed> $options
   *   Command options.
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
      $result = $this->killSwitch->breakGlass(
        $batch,
        $action,
        $identity,
        $this->optionTtl($options),
      );
      $this->printResult($result);
      $this->output()->writeln('break_glass: ' . $action->value);
      return self::EXIT_SUCCESS;
    });
  }

  /**
   * List held webhook deliveries.
   *
   * @param array<string, mixed> $options
   *   Command options.
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
          $this->displayString($row['id'] ?? ''),
          $this->displayString($row['endpoint_id'] ?? ''),
          $this->displayString($row['event_name'] ?? ''),
          $this->displayString($row['principal_key'] ?? ''),
          $this->displayString($row['human_key'] ?? ''),
          $this->displayString($row['tenant'] ?? ''),
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
   *
   * @param array<string, mixed> $options
   *   Command options.
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
   *
   * @param array<string, mixed> $options
   *   Command options.
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
   *
   * @param array<string, mixed> $options
   *   Command options.
   */
  #[CLI\Command(name: 'mcp-sentinel:unkill', aliases: ['mcps:unkill'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub.')]
  #[CLI\Option(name: 'tenant', description: 'Tenant selector.')]
  #[CLI\Option(name: 'reason', description: 'Operator reason. Required. No tokens.')]
  #[CLI\Option(name: 'confirm-batch', description: 'Batch id from an un-kill request, to confirm as the named second person (secondary account holder).')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:unkill --operator=alice --principal-key=\'iss|sub|actor\' --reason="restored"', description: 'Request an un-kill (pending confirm).')]
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
      $confirmBatch = trim($this->optionString($options, 'confirm-batch'));
      if ($confirmBatch !== '') {
        $result = $this->killSwitch->confirmUnkill($confirmBatch, $identity);
        $this->printResult($result);
        return self::EXIT_SUCCESS;
      }
      $result = $this->killSwitch->requestUnkill(
        $this->selectorsFromOptions($options),
        $this->optionString($options, 'reason'),
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
   *
   * @param array<string, mixed> $options
   *   Command options.
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
    return $this->bindWithPaladinToken($options, function (string $token) use ($options): int {
      $account = $this->accountFromOperatorOption($options);
      return $this->switchToAccountAndRun($account, function () use ($token, $account): int {
        $operatorId = $this->operatorBindings->bindFromToken($token, $account);
        $this->output()->writeln('operator_id: ' . $operatorId);
        return self::EXIT_SUCCESS;
      });
    });
  }

  /**
   * Unbind an operator record. Two distinct Paladin operators required.
   *
   * @param array<string, mixed> $options
   *   Command options.
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
      $confirmBatch = trim($this->optionString($options, 'confirm-batch'));
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
   *
   * @param array<string, mixed> $options
   *   Command options.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-status', aliases: ['mcps:kill-status'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub.')]
  #[CLI\Option(name: 'tenant', description: 'Tenant selector.')]
  #[CLI\Option(name: 'operator', description: 'Drupal account name bound to this Paladin token.')]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-status --operator=alice --principal-key=\'iss|sub|actor\'', description: 'Print the kill-block row for one principal.')]
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
        $this->logError('kill-status requires exactly one selector.');
        return self::EXIT_FAILURE;
      }
      $row = $this->killSwitch->status($selectors[0]);
      if ($row === NULL) {
        $this->output()->writeln('status: active');
        return self::EXIT_SUCCESS;
      }
      foreach ([
        'status' => $this->displayString($row['status'] ?? ''),
        'selector_type' => $this->displayString($row['selector_type'] ?? ''),
        'selector_key' => $this->displayString($row['selector_key'] ?? ''),
        'block_until' => $this->displayString($row['block_until'] ?? ''),
        'ttl' => $this->displayString($row['ttl'] ?? ''),
        'batch_id' => $this->displayString($row['batch_id'] ?? ''),
        'requested_by' => $this->displayString($row['requested_by'] ?? ''),
        'confirmed_by' => $this->displayString($row['confirmed_by'] ?? ''),
        'unkill_batch_id' => $this->displayString($row['unkill_batch_id'] ?? ''),
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
      $item = trim($this->displayString($item));
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
   * value is returned so the caller can refuse missing_token. Bind
   * reads this once and passes the string through; it does not read
   * stdin again.
   *
   * @param array<string, mixed> $options
   *   Command options.
   *
   * @return string
   *   Access token, or empty when neither source provided one.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When --token is passed or the token exceeds TOKEN_MAX_BYTES.
   */
  private function paladinToken(array $options): string {
    if (trim($this->optionString($options, 'token')) !== '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::TOKEN_FLAG_REFUSED,
        'Do not pass --token. Pipe the token on stdin or set PALADIN_TOKEN.',
      );
    }
    $fromEnv = getenv('PALADIN_TOKEN');
    if (is_string($fromEnv) && trim($fromEnv) !== '') {
      $token = trim($fromEnv);
      $this->assertTokenSize($token);
      return $token;
    }
    $stream = $this->stdinStream();
    if ($stream === NULL) {
      return '';
    }
    $line = fgets($stream, self::TOKEN_MAX_BYTES + 2);
    if ($line === FALSE) {
      return '';
    }
    $ended = str_ends_with($line, "\n") || str_ends_with($line, "\r");
    if (!$ended && strlen($line) > self::TOKEN_MAX_BYTES) {
      $this->assertTokenSize($line);
    }
    $token = trim($line);
    $this->assertTokenSize($token);
    return $token;
  }

  /**
   * Refuses a token larger than TOKEN_MAX_BYTES.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertTokenSize(string $token): void {
    if ($this->weakened(self::WEAKEN_SKIP_TOKEN_SIZE)) {
      return;
    }
    if (strlen($token) > self::TOKEN_MAX_BYTES) {
      throw new McpKillSwitchException(
        McpKillSwitchException::TOKEN_TOO_LARGE,
        'The Paladin access token is too large.',
      );
    }
  }

  /**
   * Stdin stream: PHPUnit override, or STDIN when it is not a TTY.
   *
   * @return resource|null
   *   Readable stream, or NULL when stdin is a TTY or unavailable.
   */
  private function stdinStream(): mixed {
    if (is_resource($this->stdinForTest)) {
      return $this->stdinForTest;
    }
    if (!defined('STDIN') || (function_exists('posix_isatty') && posix_isatty(STDIN))) {
      return NULL;
    }
    return STDIN;
  }

  /**
   * PHPUnit-only stdin replacement so bind can be tested without PALADIN_TOKEN.
   *
   * @param resource $stream
   *   Readable stream containing one token line.
   *
   * @internal
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function setStdinForTest(mixed $stream): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'setStdinForTest exists only under PHPUnit.',
      );
    }
    if (!is_resource($stream)) {
      throw new \InvalidArgumentException('setStdinForTest requires a stream resource.');
    }
    $this->stdinForTest = $stream;
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
    return $this->runWithPaladinToken($options, function (McpOperatorIdentity $identity) use ($options, $callback): int {
      $account = $this->mappedAccount($identity);
      $this->assertOperatorOption($options, $account);
      return $this->switchToAccountAndRun($account, static function () use ($callback, $identity): int {
        return $callback($identity);
      });
    });
  }

  /**
   * Reads the token once, then runs the callback.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param callable(string): int $callback
   *   Work that receives the Paladin token string.
   */
  private function withPaladinToken(array $options, callable $callback): int {
    try {
      $token = $this->paladinToken($options);
      return $callback($token);
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logError($e->reasonCode . ': ' . $e->getMessage());
      $this->auditCommandRefusal($e, $options);
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Reads the token once, forms a Paladin identity, then runs the callback.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param callable(\Drupal\mcp_sentinel\Value\McpOperatorIdentity): int $callback
   *   Work after the token is verified.
   */
  private function runWithPaladinToken(array $options, callable $callback): int {
    return $this->withPaladinToken($options, function (string $token) use ($callback): int {
      return $callback($this->operatorIdentities->fromPaladinToken($token));
    });
  }

  /**
   * Reads the token once and passes the string to bind. Does not switch.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param callable(string): int $callback
   *   Bind work. Receives the token; must not read stdin again.
   */
  private function bindWithPaladinToken(array $options, callable $callback): int {
    return $this->withPaladinToken($options, function (string $token) use ($callback): int {
      if ($token === '') {
        throw new McpKillSwitchException(
          McpKillSwitchException::MISSING_TOKEN,
          'A Paladin access token is required.',
        );
      }
      return $callback($token);
    });
  }

  /**
   * Switch to the mapped account, check permission, then switch back.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal account bound to the Paladin token.
   * @param callable(): int $callback
   *   Work to run as $account.
   */
  private function switchToAccountAndRun(UserInterface $account, callable $callback): int {
    $this->accountSwitcher->switchTo($account);
    try {
      if (!$this->weakened(self::WEAKEN_SKIP_PERMISSION)) {
        $this->killSwitch->assertOperatorAccess($account);
      }
      return $callback();
    }
    finally {
      if (!$this->weakened(self::WEAKEN_SKIP_SWITCH_BACK)) {
        $this->accountSwitcher->switchBack();
      }
    }
  }

  /**
   * HMAC audit for a refused command. Never includes the token.
   *
   * @param \Drupal\mcp_sentinel\Exception\McpKillSwitchException|\Drupal\mcp_sentinel\Exception\McpPrincipalKeyException $e
   *   Refusal already thrown by token, bind, or identity checks.
   * @param array<string, mixed> $options
   *   Command options.
   */
  private function auditCommandRefusal(McpKillSwitchException|McpPrincipalKeyException $e, array $options): void {
    if ($this->weakened(self::WEAKEN_SKIP_COMMAND_REFUSAL_AUDIT)) {
      return;
    }
    if ($e instanceof McpKillSwitchException && $e->alreadyAudited) {
      return;
    }
    $meta = $this->operatorIdentities->advisoryProcessMetadata();
    $this->auditLogger->logAlways(self::AUDIT_COMMAND_REFUSED, [
      'reason_code' => $e->reasonCode,
      'operator' => $this->auditOperatorName($this->optionString($options, 'operator')),
      'os_user' => $meta['os_user'] ?? '',
    ]);
  }

  /**
   * Caps and strips control characters from --operator for audit rows.
   */
  private function auditOperatorName(string $name): string {
    $clean = preg_replace('/[\x00-\x1F\x7F]/', '', $name);
    $clean = is_string($clean) ? $clean : '';
    $clean = trim($clean);
    if (strlen($clean) > 64) {
      return mb_strcut($clean, 0, 64);
    }
    return $clean;
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
    $name = trim($this->optionString($options, 'operator'));
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
    $name = trim($this->optionString($options, 'operator'));
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
   * Logs an operator-facing error when Drush attached a logger.
   */
  private function logError(string $message): void {
    $this->logger()?->error($message);
  }

  /**
   * String option, or empty when unset or not a string.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param string $key
   *   Option name.
   */
  private function optionString(array $options, string $key): string {
    $value = $options[$key] ?? '';
    return is_string($value) ? $value : '';
  }

  /**
   * Optional TTL in seconds, or NULL when --ttl is omitted.
   *
   * A bare `--ttl` (boolean TRUE from Drush), an empty `--ttl=`,
   * or any value that is not an int or integer string is refused
   * (`invalid_ttl`). Zero and negative ints go to
   * McpKillTtl::resolve, which refuses them (`invalid_ttl`).
   *
   * @param array<string, mixed> $options
   *   Command options.
   */
  private function optionTtl(array $options): ?int {
    if (($options['ttl'] ?? NULL) === NULL) {
      return NULL;
    }
    $value = $options['ttl'];
    if (is_int($value)) {
      return $value;
    }
    if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
      return (int) $value;
    }
    throw new McpKillSwitchException(
      McpKillSwitchException::INVALID_TTL,
      'Kill-block TTL must be an integer number of seconds.',
    );
  }

  /**
   * Whether a Drush boolean option is on.
   *
   * @param array<string, mixed> $options
   *   Command options.
   * @param string $key
   *   Option name.
   */
  private function optionFlag(array $options, string $key): bool {
    $value = $options[$key] ?? FALSE;
    if ($value === FALSE || $value === ''
      || $value === 0 || $value === '0' || $value === []) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Display string for a mixed table cell or status field.
   */
  private function displayString(mixed $value): string {
    if (is_string($value)) {
      return $value;
    }
    if (is_int($value) || is_float($value)) {
      return (string) $value;
    }
    return '';
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
    $keep = $this->optionFlag($options, 'keep');
    $extend = $this->optionFlag($options, 'extend');
    $lift = $this->optionFlag($options, 'lift');
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
