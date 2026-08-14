<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests McpReadBudgetResolver: finite-by-default read budgets (#3616540).
 *
 * An unlimited (0) profile cap no longer means "no budget": with
 * require_finite_read_budgets enabled (the default), unlimited values resolve
 * to the finite defaults in mcp_sentinel.settings:read_budget_defaults. An
 * explicit finite profile value always wins. Disabling the requirement is the
 * documented non-production override and restores unlimited behavior.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpReadBudgetResolverTest extends KernelTestBase {

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
    // The runtime requirements hook renders settings-form links, which walks
    // the alias manager; its entity schema must exist for that test.
    $this->installEntitySchema('path_alias');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Loads the default profile fresh from config.
   */
  private function defaultProfile(): McpPolicyProfile {
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    return McpPolicyProfile::load('default');
  }

  /**
   * Returns the resolver service.
   */
  private function resolver(): object {
    return $this->container->get('mcp_sentinel.read_budgets');
  }

  /**
   * Finite enforcement is the default: an absent key means TRUE.
   */
  public function testFiniteEnforcementDefaultsOn(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->clear('require_finite_read_budgets')->save();
    $this->assertTrue($this->resolver()->finiteBudgetsRequired());
  }

  /**
   * Unlimited profile caps clamp to the configured finite defaults.
   */
  public function testUnlimitedCapsClampToDefaults(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', [
        'results' => 7,
        'bytes' => 1024,
        'requests' => 3,
        'request_window' => 30,
        'pages' => 5,
        'page_window' => 40,
      ])
      ->save();
    $profile = $this->defaultProfile();
    $resolver = $this->resolver();
    $this->assertSame(7, $resolver->effectiveResultCap($profile));
    $this->assertSame(1024, $resolver->effectiveResponseSizeCap($profile));
    $this->assertSame([3, 30], $resolver->effectiveRateLimit($profile));
    $this->assertSame([5, 40], $resolver->pageBudget());
  }

  /**
   * An explicit finite profile value wins, even above the default.
   */
  public function testExplicitFiniteProfileValueWins(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['results' => 7, 'bytes' => 1024])
      ->save();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10000)
      ->set('response_size_cap', 99999999)
      ->set('rate_limit_requests', 900)
      ->set('rate_limit_window', 10)
      ->save();
    $profile = $this->defaultProfile();
    $resolver = $this->resolver();
    $this->assertSame(10000, $resolver->effectiveResultCap($profile));
    $this->assertSame(99999999, $resolver->effectiveResponseSizeCap($profile));
    $this->assertSame([900, 10], $resolver->effectiveRateLimit($profile));
  }

  /**
   * The explicit override restores unlimited (0) behavior.
   */
  public function testOverrideRestoresUnlimited(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', FALSE)
      ->save();
    $profile = $this->defaultProfile();
    $resolver = $this->resolver();
    $this->assertSame(0, $resolver->effectiveResultCap($profile));
    $this->assertSame(0, $resolver->effectiveResponseSizeCap($profile));
    $this->assertSame([0, 0], $resolver->effectiveRateLimit($profile));
    $this->assertSame([0, 0], $resolver->pageBudget());
  }

  /**
   * A finite operator request count is never widened by a zero window.
   */
  public function testFiniteRequestsWithZeroWindowKeepsRequests(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['request_window' => 45])
      ->save();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('rate_limit_requests', 300)
      ->set('rate_limit_window', 0)
      ->save();
    $this->assertSame([300, 45], $this->resolver()->effectiveRateLimit($this->defaultProfile()));
  }

  /**
   * Missing defaults fall back to the built-in constants, never to unlimited.
   */
  public function testMissingDefaultsFallBackToConstants(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->clear('read_budget_defaults')
      ->save();
    $profile = $this->defaultProfile();
    $resolver = $this->resolver();
    $this->assertGreaterThan(0, $resolver->effectiveResultCap($profile));
    $this->assertGreaterThan(0, $resolver->effectiveResponseSizeCap($profile));
    [$requests, $window] = $resolver->effectiveRateLimit($profile);
    $this->assertGreaterThan(0, $requests);
    $this->assertGreaterThan(0, $window);
    [$pages, $pageWindow] = $resolver->pageBudget();
    $this->assertGreaterThan(0, $pages);
    $this->assertGreaterThan(0, $pageWindow);
  }

  /**
   * The exfiltration guard truncates at the clamped default cap.
   */
  public function testGuardClampsUnlimitedResultCap(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['results' => 3])
      ->save();
    $profile = $this->defaultProfile();
    $this->assertSame(0, $profile->getResultCountCap(), 'Precondition: profile cap is unlimited.');
    /** @var \Drupal\mcp_sentinel\Service\McpExfiltrationGuard $guard */
    $guard = $this->container->get('mcp_sentinel.exfiltration_guard');
    [$capped, $truncated] = $guard->capResults(['a', 'b', 'c', 'd', 'e'], $profile);
    $this->assertCount(3, $capped);
    $this->assertTrue($truncated);
    $this->assertSame(3, $guard->effectiveResultCap($profile));
  }

  /**
   * The exfiltration guard enforces the clamped default byte cap.
   */
  public function testGuardClampsUnlimitedResponseSizeCap(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['bytes' => 10])
      ->save();
    $profile = $this->defaultProfile();
    /** @var \Drupal\mcp_sentinel\Service\McpExfiltrationGuard $guard */
    $guard = $this->container->get('mcp_sentinel.exfiltration_guard');
    $this->assertTrue($guard->exceedsResponseSizeCap(11, $profile));
    $this->assertFalse($guard->exceedsResponseSizeCap(10, $profile));
    $this->assertSame(10, $guard->effectiveResponseSizeCap($profile));
  }

  /**
   * The rate limiter throttles at the clamped default request budget.
   */
  public function testRateLimiterClampsUnlimitedBudget(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['requests' => 2, 'request_window' => 60])
      ->save();
    $profile = $this->defaultProfile();
    $this->assertSame(0, $profile->getRateLimitRequests(), 'Precondition: profile rate limit is unlimited.');
    /** @var \Drupal\mcp_sentinel\Service\McpRateLimiter $limiter */
    $limiter = $this->container->get('mcp_sentinel.rate_limiter');
    $this->assertTrue($limiter->check($profile, 5, NULL));
    $limiter->register($profile, 5, NULL);
    $this->assertTrue($limiter->check($profile, 5, NULL));
    $limiter->register($profile, 5, NULL);
    $this->assertFalse($limiter->check($profile, 5, NULL), 'Third request in the window is throttled.');
  }

  /**
   * Budget accounting is per principal (tenant boundary, concurrent quota).
   *
   * One uid at its limit leaves another uid's budget unaffected.
   */
  public function testBudgetAccountingIsPerPrincipal(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['requests' => 1, 'request_window' => 60])
      ->save();
    $profile = $this->defaultProfile();
    /** @var \Drupal\mcp_sentinel\Service\McpRateLimiter $limiter */
    $limiter = $this->container->get('mcp_sentinel.rate_limiter');
    $limiter->register($profile, 5, NULL);
    $this->assertFalse($limiter->check($profile, 5, NULL), 'uid 5 exhausted its budget.');
    $this->assertTrue($limiter->check($profile, 6, NULL), 'uid 6 has an independent budget.');
  }

  /**
   * The runtime requirements report flags the non-production override.
   */
  public function testRequirementsWarnOnOverride(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', FALSE)
      ->save();
    \Drupal::moduleHandler()->loadInclude('mcp_sentinel', 'install');
    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_read_budgets', $requirements);
    $this->assertSame(REQUIREMENT_WARNING, $requirements['mcp_sentinel_read_budgets']['severity']);

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->save();
    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayNotHasKey('mcp_sentinel_read_budgets', $requirements);
  }

}
