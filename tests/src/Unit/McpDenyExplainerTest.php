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

  /**
   * Spoofed identity arguments stay denied.
   *
   * @covers ::explain
   */
  public function testReservedIdentityArgumentStaysDenied(): void {
    $explained = (new McpDenyExplainer())->explain(
      'Tool arguments must not carry identity or tenant keys (user). Identity comes from the validated token context.',
    );
    $this->assertSame('reserved_identity_argument', $explained->ruleId);
    $this->assertFalse($explained->widenAppropriate);
  }

  /**
   * A missing tenant claim on a network call stays denied.
   *
   * @covers ::explain
   */
  public function testMissingTenantClaimStaysDenied(): void {
    $explained = (new McpDenyExplainer())->explain(
      'Network calls require a tenant claim on the validated token.',
    );
    $this->assertSame('missing_tenant_claim', $explained->ruleId);
    $this->assertFalse($explained->widenAppropriate);
    $this->assertStringNotContainsString('DEV-', $explained->nextStep);
  }

  /**
   * A missing required OAuth scope stays denied.
   *
   * @covers ::explain
   */
  public function testRequiredScopeMissingStaysDenied(): void {
    $explained = (new McpDenyExplainer())->explain(
      'The token is missing the exact required OAuth scope.',
    );
    $this->assertSame('required_scope_missing', $explained->ruleId);
    $this->assertFalse($explained->widenAppropriate);
  }

  /**
   * A missing Spoofchecker stays denied.
   *
   * @covers ::explain
   */
  public function testLookalikeCheckUnavailableStaysDenied(): void {
    $explained = (new McpDenyExplainer())->explain(
      'Reserved-key look-alike detection requires ext-intl Spoofchecker.',
    );
    $this->assertSame('lookalike_check_unavailable', $explained->ruleId);
    $this->assertFalse($explained->widenAppropriate);
  }

  /**
   * Callers receive a generic deny; annotate stays operator-only.
   *
   * @covers ::refuse
   * @covers ::annotate
   */
  public function testRefuseHidesTheRuleSuffix(): void {
    $explainer = new McpDenyExplainer();
    $caller = $explainer->refuse(
      'Network calls require a tenant claim on the validated token.',
    );
    $this->assertSame(McpDenyExplainer::CALLER_MESSAGE, $caller);
    $this->assertStringNotContainsString('[rule:', $caller);
    $annotated = $explainer->annotate(
      'Network calls require a tenant claim on the validated token.',
    );
    $this->assertStringContainsString('[rule:missing_tenant_claim', $annotated);
    $this->assertNotSame($caller, $annotated);
  }

  /**
   * CallerMessage() still returns the generic deny and emits a deprecation.
   *
   * Captures E_USER_DEPRECATED with a process error handler so the
   * assertion does not depend on UnitTestCase::expectDeprecation().
   * Core 11.4 deprecates ExpectDeprecationTrait for removal in
   * drupal:12.0.0 (https://www.drupal.org/node/3545276); composer.json
   * already declares ^12, where UnitTestCase no longer has that API.
   * The compared string must stay exact so a silent getter fails.
   *
   * @covers ::callerMessage
   */
  public function testCallerMessageIsDeprecated(): void {
    $triggered = NULL;
    set_error_handler(static function (int $errno, string $errstr) use (&$triggered): bool {
      if ($errno === E_USER_DEPRECATED) {
        $triggered = $errstr;
        return TRUE;
      }
      return FALSE;
    });
    try {
      $explainer = new McpDenyExplainer();
      // @phpstan-ignore method.deprecated (this test is the deprecation contract)
      $message = $explainer->callerMessage();
    }
    finally {
      restore_error_handler();
    }
    $this->assertSame(McpDenyExplainer::CALLER_MESSAGE, $message);
    $this->assertSame(
      'Drupal\mcp_sentinel\Service\McpDenyExplainer::callerMessage() is deprecated in mcp_sentinel:3.6.2 and is removed from mcp_sentinel:4.0.0. Use McpDenyExplainer::refuse() or McpDenyExplainer::CALLER_MESSAGE instead. See https://github.com/Wilkes-Liberty/mcp_sentinel/pull/409',
      $triggered,
    );
  }

  /**
   * Refuse() logs the explainer and returns only the generic caller deny.
   *
   * @covers ::refuse
   */
  public function testRefuseReturnsCallerMessageOnly(): void {
    $explainer = new McpDenyExplainer();
    $this->assertSame(
      McpDenyExplainer::CALLER_MESSAGE,
      $explainer->refuse('Source IP not permitted by MCP Sentinel policy.'),
    );
    $this->assertSame(
      'no_governance_profile',
      $explainer->explain('MCP Sentinel denied: no governance profile applies to this account.')->ruleId,
    );
    $this->assertSame(
      'deny_publish',
      $explainer->explain('publishing is not permitted for this agent')->ruleId,
    );
  }

  /**
   * A NULL dispatcher is named separately from a missing caller token.
   *
   * @covers ::explain
   */
  public function testMissingDispatcherIsDistinctFromMissingPrincipal(): void {
    $explainer = new McpDenyExplainer();
    $dispatcher = $explainer->explain('missing_dispatcher');
    $this->assertSame('missing_dispatcher', $dispatcher->ruleId);
    $this->assertFalse($dispatcher->widenAppropriate);
    $this->assertStringContainsString('dispatcher', $dispatcher->nextStep);
    $this->assertStringContainsString('container', $dispatcher->nextStep);
    $this->assertStringNotContainsString('Paladin', $dispatcher->nextStep);
    $this->assertStringNotContainsString('DEV-', $dispatcher->nextStep);

    $principal = $explainer->explain('missing_principal');
    $this->assertSame('missing_principal', $principal->ruleId);
    $this->assertFalse($principal->widenAppropriate);
    $this->assertStringContainsString('Paladin', $principal->nextStep);
    $this->assertStringNotContainsString('dispatcher', $principal->nextStep);
  }

  /**
   * An azp / act.sub collision is named, not folded into missing_principal.
   *
   * @covers ::explain
   */
  public function testActorClaimCollisionIsNamed(): void {
    $explained = (new McpDenyExplainer())->explain(
      'actor_claim_collision A verified principal context is required.',
    );
    $this->assertSame('actor_claim_collision', $explained->ruleId);
    $this->assertFalse($explained->widenAppropriate);
    $this->assertStringContainsString('azp', $explained->nextStep);
    $this->assertStringContainsString('act:', $explained->nextStep);
    $this->assertStringContainsString('prefix', $explained->nextStep);
    $this->assertStringNotContainsString(
      'missing_principal',
      $explained->format(),
    );
    $this->assertStringNotContainsString('DEV-', $explained->nextStep);
  }

  /**
   * An unsupported GraphQL operation kind is named, not unspecified.
   *
   * @covers ::explain
   */
  public function testGraphqlOperationTypeIsNamed(): void {
    $explained = (new McpDenyExplainer())->explain('graphql_operation_type');
    $this->assertSame('graphql_operation_type', $explained->ruleId);
    $this->assertSame(
      'unsupported GraphQL operation kind',
      $explained->ruleName,
    );
    $this->assertFalse($explained->widenAppropriate);
    $this->assertStringContainsString('query', $explained->nextStep);
    $this->assertStringNotContainsString('unspecified', $explained->format());
  }

}
