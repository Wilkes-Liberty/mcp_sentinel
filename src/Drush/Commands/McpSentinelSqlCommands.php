<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Service\McpRawSqlGuard;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * The governed raw-SQL surface.
 *
 * Why this command exists at all, given `drush sql:query` already runs SQL:
 * because `sql:query` cannot be governed. It declares
 * `Bootstrap(level: MAX, max_level: CONFIGURATION)`, and Drupal module command
 * files — hooks included — are only discovered in `bootstrapDrupalFull()`. The
 * module system is therefore never loaded on that command's path, so no hook,
 * subscriber or policy check in any Drupal module can fire for it, ever. An
 * agent reaching `sql:query` over SSH is reading the database with the entity
 * API, the deny lists, DLP and the audit chain all bypassed — which is exactly
 * how a `profile` entity on every deny list could still be read out of
 * `profile__field_nda_date`.
 *
 * A module-provided command has the opposite property: it is only reachable
 * *after* a full bootstrap (Drush bootstraps max when a command is not found
 * pre-bootstrap), so the container, the policy profile and the audit chain are
 * all available. Moving the execution point here is what makes one policy
 * govern both paths.
 *
 * Three gates, all fail-closed:
 *   1. Governance must be on, and audit logging must be on. Raw SQL that
 *      cannot be recorded is not run — an unrecorded read is the thing the
 *      product claim is supposed to rule out.
 *   2. The resolved profile must set `allow_raw_sql`. It ships FALSE.
 *   3. McpRawSqlGuard must accept the statement against that same profile.
 *
 * Every invocation is written to the tamper-evident chain with the statement
 * text — the refused ones too, because a refusal is the more interesting
 * forensic record.
 *
 * @see \Drupal\mcp_sentinel\Service\McpRawSqlGuard
 */
final class McpSentinelSqlCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * Constructs a new McpSentinelSqlCommands object.
   */
  public function __construct(
    #[Autowire(service: 'config.factory')]
    private readonly ConfigFactoryInterface $configFactory,
    #[Autowire(service: 'entity_type.manager')]
    private readonly EntityTypeManagerInterface $entityTypeManager,
    #[Autowire(service: 'mcp_sentinel.policy_resolver')]
    private readonly McpPolicyResolver $policyResolver,
    #[Autowire(service: 'mcp_sentinel.raw_sql_guard')]
    private readonly McpRawSqlGuard $rawSqlGuard,
    #[Autowire(service: 'mcp_sentinel.audit_logger')]
    private readonly McpAuditLogger $auditLogger,
    #[Autowire(service: 'database')]
    private readonly Connection $database,
  ) {
    parent::__construct();
  }

  /**
   * Run a read-only SQL query under an MCP Sentinel policy profile.
   */
  #[CLI\Command(name: 'mcp-sentinel:sql-query', aliases: ['mcps:sqlq'])]
  #[CLI\Argument(name: 'query', description: 'A single SELECT statement.')]
  #[CLI\Option(name: 'profile', description: 'Policy profile ID to enforce. Defaults to the profile governing the configured governed roles.')]
  #[CLI\Usage(name: "drush mcp-sentinel:sql-query 'SELECT nid, title FROM node_field_data'", description: 'Run a governed query under the default profile.')]
  #[CLI\Usage(name: "drush mcp-sentinel:sql-query --profile=readonly 'SELECT COUNT(*) FROM node_field_data'", description: 'Run a governed query under a named profile.')]
  public function sqlQuery(string $query = '', array $options = ['profile' => NULL]): int {
    $config = $this->configFactory->get('mcp_sentinel.settings');

    if (!$config->get('enabled')) {
      return $this->refuse($query, NULL, ['MCP Sentinel governance is disabled; raw SQL is refused.']);
    }
    // Refusing when auditing is off is not belt-and-braces, it is the point:
    // the capability's whole justification is that every use is recorded, so
    // with recording off there is nothing left to justify it.
    if (!$config->get('audit_enabled')) {
      return $this->refuse($query, NULL, ['Audit logging is disabled; raw SQL is refused because it could not be recorded.']);
    }

    $profile = $this->resolveProfile((string) ($options['profile'] ?? ''));
    if ($profile === NULL) {
      return $this->refuse($query, NULL, [
        (string) ($options['profile'] ?? '') !== ''
          ? sprintf("Policy profile '%s' does not exist.", (string) $options['profile'])
          : 'No policy profile resolved for the configured governed roles.',
      ]);
    }

    if (!$profile->allowsRawSql()) {
      return $this->refuse($query, $profile, [
        sprintf(
          "Policy profile '%s' does not permit raw SQL. Enable 'allow_raw_sql' on the profile if this is a deliberate, reviewed decision.",
          $profile->id(),
        ),
      ]);
    }

    $errors = $this->rawSqlGuard->check($query, $profile);
    if ($errors !== []) {
      return $this->refuse($query, $profile, $errors);
    }

    $cap = $profile->getResultCountCap();
    $limit = ($cap > 0) ? $cap + 1 : 0;

    try {
      $statement = $this->database->query($query);
      $rows = [];
      while (($row = $statement->fetchAssoc()) !== FALSE) {
        $rows[] = $row;
        if ($limit > 0 && count($rows) >= $limit) {
          break;
        }
      }
    }
    catch (\Throwable $e) {
      // The driver's message can echo the statement and, with it, whatever the
      // caller put in a literal; it is recorded in the audit row but not
      // returned verbatim to the caller.
      $this->refuse($query, $profile, ['The statement failed to execute.'], $e->getMessage());
      return self::EXIT_FAILURE;
    }

    // The exfiltration guard's result cap applies here exactly as it does to a
    // governed tool response — a policy that caps result size should not be
    // silently wider on this path.
    $cap = $profile->getResultCountCap();
    $total = count($rows);
    $truncated = $cap > 0 && $total > $cap;
    if ($truncated) {
      $rows = array_slice($rows, 0, $cap);
    }

    $this->auditLogger->log('raw_sql_query', [
      'channel' => 'drush',
      'profile' => $profile->id(),
      'statement' => $query,
      'row_count' => count($rows),
      'truncated' => $truncated,
    ]);

    $this->output()->writeln((string) json_encode([
      'rows' => $rows,
      'row_count' => count($rows),
      'truncated' => $truncated,
      'profile' => $profile->id(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

    return self::EXIT_SUCCESS;
  }

  /**
   * Records a refusal in the audit chain and reports it to the caller.
   *
   * @param string $query
   *   The statement as submitted.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface|null $profile
   *   The resolved profile, or NULL when refusal happened before resolution.
   * @param string[] $reasons
   *   Why the statement was refused.
   * @param string $detail
   *   Optional extra detail recorded in the audit row but not printed.
   *
   * @return int
   *   Always EXIT_FAILURE.
   */
  private function refuse(string $query, ?McpPolicyProfileInterface $profile, array $reasons, string $detail = ''): int {
    // Logged regardless of the audit_log_reads suppression path (when
    // auditing is enabled): 'raw_sql_denied' is not an entity_read or
    // config_read operation, so audit_log_reads does not gate it. A refused
    // raw-SQL attempt is a security event and is recorded even when read
    // logging is off.
    $metadata = [
      'channel' => 'drush',
      'profile' => $profile?->id() ?? '(unresolved)',
      'statement' => $query,
      'reasons' => $reasons,
    ];
    if ($detail !== '') {
      $metadata['detail'] = $detail;
    }
    $this->auditLogger->log('raw_sql_denied', $metadata);

    foreach ($reasons as $reason) {
      $this->logger()->error($reason);
    }

    return self::EXIT_FAILURE;
  }

  /**
   * Resolves the profile to enforce.
   *
   * With an explicit --profile the named profile is used and a miss is an
   * error, never a silent fall back to a more permissive default. Without one,
   * the profile governing the configured governed roles is used, so the CLI
   * path enforces the same profile the agent's HTTP traffic would.
   *
   * @param string $profileId
   *   The --profile option value, or '' when not supplied.
   *
   * @return \Drupal\mcp_sentinel\McpPolicyProfileInterface|null
   *   The profile, or NULL when none resolves.
   */
  private function resolveProfile(string $profileId): ?McpPolicyProfileInterface {
    if ($profileId !== '') {
      $profile = $this->entityTypeManager
        ->getStorage('mcp_policy_profile')
        ->load($profileId);
      return $profile instanceof McpPolicyProfileInterface ? $profile : NULL;
    }

    $governedRoles = (array) ($this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('governed_roles') ?? []);

    return $this->policyResolver->resolveForRoles($governedRoles);
  }

}
