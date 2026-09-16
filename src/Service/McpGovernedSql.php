<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Exception\McpSqlRefusal;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Runs bounded SELECT statements through one policy, DLP and audit path.
 *
 * The adapter resolves the policy: CLI can select a reviewed profile, while
 * Tool API must use the authenticated account's profile. No database fallback
 * is permitted after any refusal or audit failure.
 */
final class McpGovernedSql {

  /**
   * Constructs the governed SELECT service.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly McpRawSqlGuard $guard,
    private readonly McpExfiltrationGuard $egress,
    private readonly McpAuditLogger $audit,
    private readonly Connection $database,
    private readonly McpClassificationResolver $classification,
    private readonly McpDlp $dlp,
    private readonly McpRateLimiter $rateLimiter,
    private readonly AccountProxyInterface $currentUser,
    private readonly McpReadBudgetResolver $budgets,
  ) {}

  /**
   * Executes an approved query, returning rows only after successful auditing.
   *
   * @return array<string, mixed>
   *   Bounded rows, row count, truncation flag and resolved profile ID.
   */
  public function run(string $query, ?McpPolicyProfileInterface $profile, McpGovernedSurface $surface): array {
    $previous = $this->classification->currentSurface();
    $this->classification->setSurface($surface);
    try {
      return $this->execute($query, $profile, $surface);
    }
    finally {
      $this->classification->setSurface($previous);
    }
  }

  /**
   * Applies the complete governed execution pipeline.
   *
   * @return array<string, mixed>
   *   The safe result.
   */
  private function execute(string $query, ?McpPolicyProfileInterface $profile, McpGovernedSurface $surface): array {
    $settings = $this->configFactory->get('mcp_sentinel.settings');
    if (!$settings->get('enabled') || !$settings->get('audit_enabled')) {
      $this->refuse($query, $profile, $surface, ['Governance and audit logging must both be enabled.']);
    }
    if ($profile === NULL || !$profile->status() || !$profile->allowsRawSql()) {
      $this->refuse($query, $profile, $surface, ['An active policy with explicit raw SQL permission is required.']);
    }
    if ($query === '' || strlen($query) > McpRawSqlGuard::MAX_LENGTH) {
      // Do not retain an unbounded submitted statement in an audit event.
      $this->refuse('', $profile, $surface, ['The statement must contain between 1 and 4096 bytes.']);
    }
    $cap = $this->egress->effectiveResultCap($profile);
    $bytes = $this->egress->effectiveResponseSizeCap($profile);
    [$requests, $window] = $this->budgets->effectiveRateLimit($profile);
    if ($cap <= 0 || $bytes <= 0 || $cap === PHP_INT_MAX || $requests <= 0 || $window <= 0) {
      $this->refuse($query, $profile, $surface, ['Finite request, result and response budgets are required for raw SQL.']);
    }
    $uid = (int) $this->currentUser->id();
    if (!$this->rateLimiter->check($profile, $uid, 'raw_sql')) {
      $this->refuse($query, $profile, $surface, ['The raw SQL request budget is exhausted.']);
    }
    $this->rateLimiter->register($profile, $uid, 'raw_sql');
    $errors = $this->guard->check($query, $profile, $surface);
    if ($errors !== []) {
      $this->refuse($query, $profile, $surface, $errors);
    }
    $executable = $this->guard->braceKnownTables($query);
    if ($executable === NULL) {
      $this->refuse($query, $profile, $surface, ['The statement could not be resolved to governed table names.']);
    }

    $rows = [];
    $truncated = FALSE;
    $usedBytes = 0;
    try {
      // Apply the output row ceiling at the database as well as in PHP. The
      // inner query retains its own WHERE, ordering and optional LIMIT.
      $statement = $this->database->queryRange(
        'SELECT * FROM (' . rtrim($executable, "; \t\n\r") . ') mcp_sentinel_result',
        0,
        $cap + 1,
      );
      $ceiling = $this->classification->effectiveCeiling($profile, $surface);
      while (($row = $statement->fetchAssoc()) !== FALSE) {
        if (count($rows) === $cap) {
          $truncated = TRUE;
          break;
        }
        $usedBytes += strlen(json_encode($row, JSON_THROW_ON_ERROR));
        if ($usedBytes > $bytes) {
          $this->refuse($query, $profile, $surface, ['The raw SQL response exceeds its byte budget.']);
        }
        $rows[] = $this->dlp->scanTree($row, $ceiling, $this->classification);
      }
    }
    catch (McpSqlRefusal $exception) {
      throw $exception;
    }
    catch (\Throwable $exception) {
      // Driver messages may contain literals; keep them out of tool errors.
      $this->refuse($query, $profile, $surface, ['The governed statement failed to execute.']);
    }
    $result = [
      'rows' => $rows,
      'row_count' => count($rows),
      'truncated' => $truncated,
      'profile' => $profile->id(),
    ];
    if (strlen(json_encode($result, JSON_THROW_ON_ERROR)) > $bytes) {
      $this->refuse($query, $profile, $surface, ['The raw SQL response exceeds its byte budget.']);
    }
    $this->audit->log('raw_sql_query', [
      'channel' => $surface->value,
      'profile' => $profile->id(),
      'statement' => $query,
      'row_count' => count($rows),
      'truncated' => $truncated,
    ]);
    return $result;
  }

  /**
   * Audits a denial and terminates without returning record values.
   *
   * @param string $query
   *   Submitted statement, retained only within the query size bound.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface|null $profile
   *   Resolved policy, or NULL if none is eligible.
   * @param \Drupal\mcp_sentinel\Enum\McpGovernedSurface $surface
   *   Adapter surface for classification and audit.
   * @param string[] $reasons
   *   Curated validation or policy reasons.
   */
  private function refuse(string $query, ?McpPolicyProfileInterface $profile, McpGovernedSurface $surface, array $reasons): never {
    $this->audit->log('raw_sql_denied', [
      'channel' => $surface->value,
      'profile' => $profile?->id() ?? '(unresolved)',
      'statement' => strlen($query) <= McpRawSqlGuard::MAX_LENGTH ? $query : '(oversized)',
      'reasons' => $reasons,
    ]);
    throw new McpSqlRefusal($reasons);
  }

}
