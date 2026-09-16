<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Exception\McpSqlRefusal;
use Drupal\mcp_sentinel\Service\McpGovernedSql;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
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
 * When auditing is enabled, accepted and refused bounded statements are
 * recorded. Oversized inputs are recorded without their body. No result is
 * returned if auditing fails. The shared service also applies finite request,
 * row and byte budgets, classification and DLP.
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
    #[Autowire(service: 'mcp_sentinel.governed_sql')]
    private readonly McpGovernedSql $governedSql,
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
    $profile = $this->resolveProfile((string) ($options['profile'] ?? ''));
    try {
      $result = $this->governedSql->run($query, $profile, McpGovernedSurface::Drush);
      $this->output()->writeln(json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
      return self::EXIT_SUCCESS;
    }
    catch (McpSqlRefusal $exception) {
      foreach ($exception->reasons as $reason) {
        $this->logger()->error($reason);
      }
    }
    catch (\Throwable $exception) {
      $this->logger()->error('Governed SQL failed; no result was returned. Check source governance and audit availability.');
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
