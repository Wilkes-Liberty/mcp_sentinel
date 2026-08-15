<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Value\McpInstallCheck;
use Drupal\mcp_sentinel\Value\McpInstallOutcome;
use Drupal\mcp_sentinel\Value\McpInstallVerificationResult;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Outcome vocabulary and evidence-document rules for the install verifier.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Value\McpInstallVerificationResult
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpInstallVerificationResult::class)]
#[CoversClass(McpInstallCheck::class)]
#[CoversClass(McpInstallOutcome::class)]
#[Group('mcp_sentinel')]
final class McpInstallVerificationResultTest extends UnitTestCase {

  /**
   * A run of only passes is ok.
   */
  public function testAllPassIsOk(): void {
    $result = $this->document([
      McpInstallCheck::pass('tenant_neutrality', 'Shipped config names no tenant'),
      McpInstallCheck::pass('finite_budgets', 'Read budgets are finite'),
    ]);
    $this->assertTrue($result->isOk());
    $this->assertSame(2, $result->summary()['pass']);
    $this->assertTrue($result->toArray()['summary']['ok']);
  }

  /**
   * A skipped check fails the run: silence is not evidence.
   */
  public function testSkippedFailsTheRun(): void {
    $result = $this->document([
      McpInstallCheck::pass('finite_budgets', 'Read budgets are finite'),
      McpInstallCheck::skipped(
        'probe_live_content_edit',
        'An edit to live content is refused',
        'no content target supplied',
      ),
    ]);
    $this->assertFalse($result->isOk());
    $this->assertSame(1, $result->summary()['skipped']);
    $this->assertFalse($result->toArray()['summary']['ok']);
  }

  /**
   * A not-applicable check does not fail the run.
   */
  public function testNotApplicableDoesNotFailTheRun(): void {
    $result = $this->document([
      McpInstallCheck::pass('finite_budgets', 'Read budgets are finite'),
      McpInstallCheck::notApplicable(
        'probe_config_change',
        'A configuration change is refused',
        'this profile grants config write',
      ),
    ]);
    $this->assertTrue($result->isOk());
    $this->assertSame(1, $result->summary()['notApplicable']);
  }

  /**
   * A failed check fails the run.
   */
  public function testFailFailsTheRun(): void {
    $result = $this->document([
      McpInstallCheck::fail(
        'no_dev_fallback',
        'Development role fallback is off',
        ['governed_role_fallback is enabled'],
      ),
    ]);
    $this->assertFalse($result->isOk());
    $this->assertSame(1, $result->summary()['fail']);
  }

  /**
   * Residuals ride on every document so a green run is not completeness.
   */
  public function testResidualsArePartOfTheDocument(): void {
    $result = $this->document([
      McpInstallCheck::pass('tenant_neutrality', 'Shipped config names no tenant'),
    ]);
    $ids = array_column($result->residuals(), 'id');
    $this->assertContains('prompt_injection', $ids);
    $this->assertContains('operator_trust', $ids);
    foreach ($result->residuals() as $residual) {
      $this->assertSame('managed', $residual['status']);
    }
  }

  /**
   * The JSON document carries versions and a digest, never a secret.
   */
  public function testJsonDocumentCarriesVersionsAndNoSecrets(): void {
    $encoded = json_encode($this->document([
      McpInstallCheck::pass('tenant_neutrality', 'Shipped config names no tenant'),
    ])->toArray(), JSON_THROW_ON_ERROR);
    $this->assertStringContainsString('"moduleVersion":"2.9.0"', $encoded);
    $this->assertStringContainsString('"drupalVersion":"10.6.0"', $encoded);
    $this->assertStringContainsString('"configDigest":"sha256:abc"', $encoded);
    $this->assertStringNotContainsString('client_secret', $encoded);
    $this->assertStringNotContainsString('webhook_secret', $encoded);
  }

  /**
   * Builds a document around the given checks.
   *
   * @param \Drupal\mcp_sentinel\Value\McpInstallCheck[] $checks
   *   Checks.
   *
   * @return \Drupal\mcp_sentinel\Value\McpInstallVerificationResult
   *   The document.
   */
  private function document(array $checks): McpInstallVerificationResult {
    return new McpInstallVerificationResult(
      '2.9.0',
      '10.6.0',
      'sha256:abc',
      'posture',
      $checks,
      [
        [
          'id' => 'prompt_injection',
          'status' => 'managed',
          'detail' => 'Prompt injection is not solved by this module.',
        ],
        [
          'id' => 'operator_trust',
          'status' => 'managed',
          'detail' => 'An operator who can run Drush can act as any principal.',
        ],
      ],
      '2026-08-15T00:00:00+00:00',
    );
  }

}
