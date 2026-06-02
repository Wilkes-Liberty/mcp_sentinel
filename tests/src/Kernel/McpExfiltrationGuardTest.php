<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests McpExfiltrationGuard: result-count cap and response-size cap.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpExfiltrationGuardTest extends KernelTestBase {

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
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * A list larger than the cap is sliced and truncated is TRUE.
   */
  public function testCapsTruncatesList(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 3)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $profile = McpPolicyProfile::load('default');
    /** @var \Drupal\mcp_sentinel\Service\McpExfiltrationGuard $guard */
    $guard = $this->container->get('mcp_sentinel.exfiltration_guard');
    [$capped, $truncated] = $guard->capResults(['a', 'b', 'c', 'd', 'e'], $profile);
    $this->assertCount(3, $capped);
    $this->assertTrue($truncated);
  }

  /**
   * A list at exactly the cap is not truncated.
   */
  public function testNoTruncationAtExactCap(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 3)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $profile = McpPolicyProfile::load('default');
    $guard = $this->container->get('mcp_sentinel.exfiltration_guard');
    [$capped, $truncated] = $guard->capResults(['a', 'b', 'c'], $profile);
    $this->assertCount(3, $capped);
    $this->assertFalse($truncated);
  }

  /**
   * When result_count_cap is 0 (unlimited) no truncation occurs.
   */
  public function testNoTruncationWhenUnlimited(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 0)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $profile = McpPolicyProfile::load('default');
    $guard = $this->container->get('mcp_sentinel.exfiltration_guard');
    [$capped, $truncated] = $guard->capResults(range(1, 1000), $profile);
    $this->assertCount(1000, $capped);
    $this->assertFalse($truncated);
  }

  /**
   * Response size above the cap returns TRUE; below returns FALSE.
   */
  public function testResponseSizeCapDetected(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('response_size_cap', 100)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $profile = McpPolicyProfile::load('default');
    $guard = $this->container->get('mcp_sentinel.exfiltration_guard');
    $this->assertTrue($guard->exceedsResponseSizeCap(500, $profile));
    $this->assertFalse($guard->exceedsResponseSizeCap(50, $profile));
  }

  /**
   * When response_size_cap is 0 (unlimited) no cap fires.
   */
  public function testResponseSizeCapUnlimited(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('response_size_cap', 0)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $profile = McpPolicyProfile::load('default');
    $guard = $this->container->get('mcp_sentinel.exfiltration_guard');
    $this->assertFalse($guard->exceedsResponseSizeCap(10_000_000, $profile));
  }

}
