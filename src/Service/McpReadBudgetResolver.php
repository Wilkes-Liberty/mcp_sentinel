<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Resolves effective, finite-by-default read budgets (#3616540).
 *
 * A profile budget of 0 used to mean "unlimited". Unlimited is not a
 * mass-read/exfiltration floor, so with require_finite_read_budgets enabled
 * (the default — an absent key counts as enabled) an unlimited value resolves
 * to the finite defaults in mcp_sentinel.settings:read_budget_defaults. An
 * explicit finite profile value always wins, even when it is larger than the
 * default: the requirement is that every budget is FINITE, not small.
 *
 * Disabling require_finite_read_budgets is the explicit non-production
 * override. It restores unlimited (0) behavior and is surfaced as a runtime
 * requirements warning, so a secure-install verification can never report
 * clean while the override is active.
 *
 * Missing entries in read_budget_defaults fall back to the built-in constants
 * rather than to unlimited: the floor exists even on a site whose settings
 * predate this feature.
 */
final class McpReadBudgetResolver {

  /**
   * Built-in default: max result items per request.
   */
  public const DEFAULT_RESULTS = 500;

  /**
   * Built-in default: max response bytes (8 MiB).
   */
  public const DEFAULT_BYTES = 8388608;

  /**
   * Built-in default: max governed requests per window.
   */
  public const DEFAULT_REQUESTS = 600;

  /**
   * Built-in default: request budget window in seconds.
   */
  public const DEFAULT_REQUEST_WINDOW = 60;

  /**
   * Built-in default: max governed collection pages per window.
   */
  public const DEFAULT_PAGES = 120;

  /**
   * Built-in default: page budget window in seconds.
   */
  public const DEFAULT_PAGE_WINDOW = 60;

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * Whether finite budgets are required (the secure default).
   *
   * @return bool
   *   TRUE unless the operator explicitly set the non-production override.
   */
  public function finiteBudgetsRequired(): bool {
    $value = $this->settings()->get('require_finite_read_budgets');
    // An absent key (site installed before this feature) is the secure
    // default, not the override: only an explicit FALSE disables clamping.
    return $value === NULL ? TRUE : (bool) $value;
  }

  /**
   * Effective max result items per request for a profile.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   *
   * @return int
   *   A positive cap, or 0 (unlimited) only under the explicit override.
   */
  public function effectiveResultCap(McpPolicyProfileInterface $profile): int {
    return $this->effective($profile->getResultCountCap(), 'results', self::DEFAULT_RESULTS);
  }

  /**
   * Effective max response bytes for a profile.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   *
   * @return int
   *   A positive cap, or 0 (unlimited) only under the explicit override.
   */
  public function effectiveResponseSizeCap(McpPolicyProfileInterface $profile): int {
    return $this->effective($profile->getResponseSizeCap(), 'bytes', self::DEFAULT_BYTES);
  }

  /**
   * Effective request budget for a profile.
   *
   * The profile pair wins only when BOTH values are positive — a finite
   * request count with a zero window is not a usable budget.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   *
   * @return array{0: int, 1: int}
   *   [requests, window_seconds]; [0, 0] only under the explicit override.
   */
  public function effectiveRateLimit(McpPolicyProfileInterface $profile): array {
    $requests = $profile->getRateLimitRequests();
    $window = $profile->getRateLimitWindow();
    if ($requests > 0) {
      // A finite operator value is never widened: a missing/zero window gets
      // the default window rather than discarding the request count.
      return [
        $requests,
        $window > 0 ? $window : $this->defaultValue('request_window', self::DEFAULT_REQUEST_WINDOW),
      ];
    }
    if (!$this->finiteBudgetsRequired()) {
      return [0, 0];
    }
    return [
      $this->defaultValue('requests', self::DEFAULT_REQUESTS),
      $this->defaultValue('request_window', self::DEFAULT_REQUEST_WINDOW),
    ];
  }

  /**
   * The collection-page budget (accounted per principal + profile).
   *
   * @return array{0: int, 1: int}
   *   [pages, window_seconds]; [0, 0] only under the explicit override.
   */
  public function pageBudget(): array {
    if (!$this->finiteBudgetsRequired()) {
      return [0, 0];
    }
    return [
      $this->defaultValue('pages', self::DEFAULT_PAGES),
      $this->defaultValue('page_window', self::DEFAULT_PAGE_WINDOW),
    ];
  }

  /**
   * Resolves one scalar budget: profile value, else clamp, else unlimited.
   */
  private function effective(int $profileValue, string $key, int $fallback): int {
    if ($profileValue > 0) {
      return $profileValue;
    }
    if (!$this->finiteBudgetsRequired()) {
      return 0;
    }
    return $this->defaultValue($key, $fallback);
  }

  /**
   * Reads one entry from read_budget_defaults, falling back to a constant.
   */
  private function defaultValue(string $key, int $fallback): int {
    $map = $this->settings()->get('read_budget_defaults');
    $value = 0;
    if (is_array($map) && isset($map[$key]) && is_numeric($map[$key])) {
      $value = (int) $map[$key];
    }
    return $value > 0 ? $value : $fallback;
  }

  /**
   * The module settings.
   */
  private function settings(): ImmutableConfig {
    return $this->configFactory->get('mcp_sentinel.settings');
  }

}
