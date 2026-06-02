<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\State\StateInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpContentLock;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Drush commands for MCP Sentinel maintenance and inspection.
 */
final class McpSentinelCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * Constructs a new McpSentinelCommands object.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    #[Autowire(service: 'mcp_sentinel.audit_logger')]
    private readonly McpAuditLogger $auditLogger,
    #[Autowire(service: 'mcp_sentinel.content_lock')]
    private readonly McpContentLock $contentLock,
    #[Autowire(service: 'database')]
    private readonly Connection $database,
    #[Autowire(service: 'entity_type.manager')]
    private readonly EntityTypeManagerInterface $entityTypeManager,
    #[Autowire(service: 'mcp_sentinel.webhook_queue_manager')]
    private readonly McpWebhookQueueManager $webhookQueueManager,
    #[Autowire(service: 'state')]
    private readonly StateInterface $state,
    #[Autowire(service: 'datetime.time')]
    private readonly TimeInterface $time,
  ) {
    parent::__construct();
  }

  /**
   * Show a summary of the current MCP Sentinel configuration and state.
   */
  #[CLI\Command(name: 'mcp-sentinel:status', aliases: ['mcps:status'])]
  #[CLI\Usage(name: 'drush mcp-sentinel:status', description: 'Print the active policy plus audit and lock counts.')]
  public function status(): int {
    $config = $this->configFactory->get('mcp_sentinel.settings');
    $bool = static fn(?bool $v): string => $v ? 'yes' : 'no';
    $list = static fn(?array $v): string => $v ? implode(', ', $v) : '(none)';

    $audit_count = (int) $this->database->select('mcp_sentinel_audit_log')->countQuery()->execute()->fetchField();
    $lock_count = (int) $this->database->select('mcp_sentinel_content_locks')->countQuery()->execute()->fetchField();

    $rows = [
      ['MCP access enabled', $bool($config->get('enabled'))],
      ['Audit logging', $bool($config->get('audit_enabled'))],
      ['Log reads', $bool($config->get('audit_log_reads'))],
      ['Audit retention (days)', (string) ((int) $config->get('audit_retention_days'))],
      ['Audit log entries', (string) $audit_count],
      ['Webhooks enabled', $bool($config->get('webhook_enabled'))],
      ['Active content locks', (string) $lock_count],
    ];
    $rows[] = ['Governed roles', $list($config->get('governed_roles'))];
    // OAuth agent-channel settings (Phase 2).
    $oauthClients = $config->get('agent_oauth_clients') ?? [];
    $oauthScopes = $config->get('agent_scopes') ?? [];
    $rows[] = [
      'OAuth agent channel',
      sprintf(
        'clients=%s | scopes=%s | role_fallback=%s',
        $oauthClients ? implode(',', $oauthClients) : '(any — scope-only mode)',
        $oauthScopes ? implode(',', $oauthScopes) : '(none)',
        $bool($config->get('governed_role_fallback')),
      ),
    ];

    $output = $this->output();
    $this->io()->title('MCP Sentinel status');
    $this->io()->table(['Setting', 'Value'], $rows);

    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface[] $profiles */
    $profiles = $this->entityTypeManager->getStorage('mcp_policy_profile')->loadMultiple();
    if ($profiles) {
      $output->writeln('');
      foreach ($profiles as $profile) {
        $output->writeln(sprintf(
          'Profile %s (roles: %s) read=%d write=%d delete=%d gql_mut=%d redacted=[%s]',
          $profile->id(),
          $profile->getRoles() ? implode(',', $profile->getRoles()) : 'default',
          (int) $profile->allowsRead(),
          (int) $profile->allowsWrite(),
          (int) $profile->allowsDelete(),
          (int) $profile->allowsGraphqlMutations(),
          implode(',', $profile->getRedactedFields()),
        ));
      }
    }

    return self::EXIT_SUCCESS;
  }

  /**
   * Prune audit log entries older than the configured retention period.
   */
  #[CLI\Command(name: 'mcp-sentinel:audit-purge', aliases: ['mcps:audit-purge'])]
  #[CLI\Usage(name: 'drush mcp-sentinel:audit-purge', description: 'Delete audit entries past the retention window now (also runs on cron).')]
  public function auditPurge(): int {
    $retention = (int) $this->configFactory->get('mcp_sentinel.settings')->get('audit_retention_days');
    if ($retention <= 0) {
      $this->logger()->notice('Audit retention is set to "forever" (0). Nothing to purge.');
      return self::EXIT_SUCCESS;
    }
    $deleted = $this->auditLogger->pruneOldEntries();
    $this->logger()->success(sprintf('Purged %d audit log entr%s older than %d days.', $deleted, $deleted === 1 ? 'y' : 'ies', $retention));
    return self::EXIT_SUCCESS;
  }

  /**
   * Release all expired content locks.
   */
  #[CLI\Command(name: 'mcp-sentinel:lock-clear', aliases: ['mcps:lock-clear'])]
  #[CLI\Usage(name: 'drush mcp-sentinel:lock-clear', description: 'Release expired content locks now (also runs on cron).')]
  public function lockClear(): int {
    $released = $this->contentLock->releaseExpired();
    $this->logger()->success(sprintf('Released %d expired content lock%s.', $released, $released === 1 ? '' : 's'));
    return self::EXIT_SUCCESS;
  }

  /**
   * Prune webhook delivery log rows older than the retention period.
   */
  #[CLI\Command(name: 'mcp-sentinel:webhook-prune', aliases: ['mcps:webhook-prune'])]
  #[CLI\Usage(name: 'drush mcp-sentinel:webhook-prune', description: 'Delete webhook delivery rows past the retention window (also runs on cron).')]
  public function webhookPrune(): int {
    $pruned = $this->webhookQueueManager->pruneOldDeliveries();
    $this->logger()->success(sprintf('Pruned %d webhook delivery row%s.', $pruned, $pruned === 1 ? '' : 's'));
    return self::EXIT_SUCCESS;
  }

  /**
   * Re-enqueue a webhook delivery row for another delivery attempt.
   */
  #[CLI\Command(name: 'mcp-sentinel:webhook-replay', aliases: ['mcps:webhook-replay'])]
  #[CLI\Argument(name: 'deliveryId', description: 'Delivery log row ID to replay.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:webhook-replay 42', description: 'Reset delivery 42 to pending and re-queue it.')]
  public function webhookReplay(int $deliveryId = 0): int {
    if ($deliveryId <= 0) {
      $this->logger()->error('Provide a positive delivery row ID, e.g. drush mcp-sentinel:webhook-replay 42.');
      return self::EXIT_FAILURE;
    }
    if (!$this->webhookQueueManager->replayDelivery($deliveryId)) {
      $this->logger()->error(sprintf('Delivery %d not found or its endpoint is no longer configured.', $deliveryId));
      return self::EXIT_FAILURE;
    }
    $this->logger()->success(sprintf('Delivery %d reset to pending and re-queued for replay.', $deliveryId));
    return self::EXIT_SUCCESS;
  }

  /**
   * Verify the tamper-evident hash chain of the audit log.
   *
   * Walks all audit rows in insertion order, recomputing each row's SHA-256
   * hash from its stored prev_hash and canonical content. Prints OK if the
   * chain is intact, or the id of the first broken link if not.
   */
  #[CLI\Command(name: 'mcp-sentinel:audit-verify', aliases: ['mcps:audit-verify'])]
  #[CLI\Usage(name: 'drush mcp-sentinel:audit-verify', description: 'Verify the tamper-evident audit log hash chain.')]
  public function auditVerify(): int {
    $result = $this->auditLogger->verifyChain();

    // Persist the verification outcome so the dashboard chain-integrity widget
    // (McpMetrics::chainIntegrity()) and the McpUrgentConditions chain_broken
    // alert reflect this run without re-running the full walk on every request.
    //
    // NOTE (Task C/D implementer): the dashboard "Verify now" action must also
    // write this same state key with the same shape so the widget stays live.
    // Shape read by chainIntegrity(): ok, broken_at, time (-> verified_at).
    $rowCount = (int) $this->database
      ->select('mcp_sentinel_audit_log', 'l')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->state->set('mcp_sentinel.last_verify', [
      'ok'        => (bool) $result['ok'],
      'broken_at' => isset($result['broken_at']) ? (int) $result['broken_at'] : NULL,
      'rows'      => $rowCount,
      'time'      => $this->time->getRequestTime(),
    ]);

    if ($result['ok']) {
      $this->logger()->success('Audit log hash chain OK — no tampering detected.');
      return self::EXIT_SUCCESS;
    }
    $this->logger()->error(sprintf(
      'Audit log hash chain BROKEN at row id %d. One or more rows have been tampered with.',
      (int) $result['broken_at'],
    ));
    return self::EXIT_FAILURE;
  }

}
