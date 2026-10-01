<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpEvidenceGuard;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Shared policy digest used by evidence precommit and approval mint.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpEvidenceGuard
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpEvidenceGuard::class)]
#[Group('mcp_sentinel')]
final class McpEvidenceGuardPolicyDigestTest extends UnitTestCase {

  /**
   * No resolved profile means no digest.
   *
   * @covers ::policyDigest
   */
  public function testNullProfileHasNoDigest(): void {
    $this->assertNull(McpEvidenceGuard::policyDigest(NULL));
  }

  /**
   * The digest is sha256 of the profile document.
   *
   * @covers ::policyDigest
   */
  public function testDigestHashesProfileDocument(): void {
    $document = ['id' => 'strict', 'weight' => 10];
    $profile = $this->createMock(McpPolicyProfileInterface::class);
    $profile->method('toArray')->willReturn($document);

    $this->assertSame(
      'sha256:' . hash('sha256', (string) json_encode($document)),
      McpEvidenceGuard::policyDigest($profile),
    );
  }

}
