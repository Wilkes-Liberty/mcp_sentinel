<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\Core\Cache\Cache;
use Drupal\Core\Cache\CacheableDependencyInterface;
use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Immutable result of a source-governance readiness decision.
 */
final class McpGovernanceReadinessResult implements CacheableDependencyInterface {

  /**
   * Constructs a readiness result.
   */
  private function __construct(
    private readonly bool $applicable,
    private readonly bool $ready,
    private readonly ?McpGovernanceReadinessReason $reason,
    private readonly ?McpPolicyProfileInterface $profile,
  ) {}

  /**
   * Creates a ready result.
   */
  public static function ready(?McpPolicyProfileInterface $profile = NULL): self {
    return new self(TRUE, TRUE, NULL, $profile);
  }

  /**
   * Creates a not-ready result.
   */
  public static function denied(
    McpGovernanceReadinessReason $reason,
    ?McpPolicyProfileInterface $profile = NULL,
  ): self {
    return new self(TRUE, FALSE, $reason, $profile);
  }

  /**
   * Creates a neutral result for ordinary non-agent Drupal traffic.
   */
  public static function notApplicable(): self {
    return new self(FALSE, FALSE, NULL, NULL);
  }

  /**
   * Whether the request belongs to a governed product path.
   */
  public function isApplicable(): bool {
    return $this->applicable;
  }

  /**
   * Whether the source-governance contract is ready.
   */
  public function isReady(): bool {
    return $this->ready;
  }

  /**
   * Returns the stable denial reason, if any.
   */
  public function reason(): ?McpGovernanceReadinessReason {
    return $this->reason;
  }

  /**
   * Returns the applicable profile, if readiness resolved one.
   */
  public function profile(): ?McpPolicyProfileInterface {
    return $this->profile;
  }

  /**
   * {@inheritdoc}
   */
  public function getCacheContexts(): array {
    return ['user.roles', 'oauth2_scopes'];
  }

  /**
   * {@inheritdoc}
   */
  public function getCacheTags(): array {
    return Cache::mergeTags(
      ['config:mcp_sentinel.settings', 'mcp_policy_profile_list', 'mcp_tool_config_list'],
      $this->profile?->getCacheTags() ?? [],
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getCacheMaxAge(): int {
    // Mutable configuration must affect the next request on the same service
    // instance. Tags are retained for callers aggregating this result.
    return 0;
  }

}
