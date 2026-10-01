<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Deny explanations name a rule and never auto-widen.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpDenyExplainer
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpDenyExplainer::class)]
#[Group('mcp_sentinel')]
final class McpDenyExplainerTest extends UnitTestCase {

  /**
   * Credential entity types must stay denied.
   *
   * @covers ::explain
   */
  public function testUserDenylistMustStayDenied(): void {
    $explained = (new McpDenyExplainer())->explain(
      "Entity type 'user' is denied by MCP Sentinel.",
    );
    $this->assertSame('entity_type_denied', $explained->ruleId);
    $this->assertFalse($explained->widenAppropriate);
    $this->assertStringContainsString('Stay denied', $explained->format());
    $this->assertStringNotContainsString('secret', $explained->format());
  }

  /**
   * Editorial allowlist misses may be widened by a human only.
   *
   * @covers ::explain
   * @covers ::annotate
   */
  public function testAllowlistMissMayBeWidenedByHuman(): void {
    $explainer = new McpDenyExplainer();
    $reason = "Entity type 'taxonomy_term' is not in the MCP Sentinel allowlist.";
    $explained = $explainer->explain($reason, 'content');
    $this->assertSame('entity_type_allowlist', $explained->ruleId);
    $this->assertTrue($explained->widenAppropriate);
    $annotated = $explainer->annotate($reason, 'content');
    $this->assertStringContainsString($reason, $annotated);
    $this->assertStringContainsString('[rule:entity_type_allowlist', $annotated);
    $this->assertStringContainsString('never automatic', $annotated);
    $this->assertSame($annotated, $explainer->annotate($annotated, 'content'));
  }

  /**
   * Response-size refusals name the cap rule and stay human-only.
   *
   * @covers ::explain
   */
  public function testResponseSizeCapIsNamed(): void {
    $explained = (new McpDenyExplainer())->explain(
      'Response size 101 bytes exceeds the MCP Sentinel cap of 100 bytes for this profile. Narrow your query.',
    );
    $this->assertSame('response_size_cap', $explained->ruleId);
    $this->assertTrue($explained->widenAppropriate);
    $this->assertStringContainsString('never automatic', $explained->format());
  }

  /**
   * Readiness codes stay denied until the named gate is fixed.
   *
   * @covers ::explain
   */
  public function testReadinessCodeDoesNotSuggestAllowlistWiden(): void {
    $explained = (new McpDenyExplainer())->explain(
      'MCP Sentinel source governance is not ready: designated_consumer_missing.',
    );
    $this->assertSame('designated_consumer_missing', $explained->ruleId);
    $this->assertFalse($explained->widenAppropriate);
    $this->assertStringContainsString('Add a Consumer', $explained->nextStep);
  }

}
