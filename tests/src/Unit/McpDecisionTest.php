<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Enum\McpDecisionOutcome;
use Drupal\mcp_sentinel\Enum\McpDecisionReason;
use Drupal\mcp_sentinel\Value\McpDecision;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Typed decision contract: outcomes, reasons, obligations.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Value\McpDecision
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpDecision::class)]
#[CoversClass(McpDecisionOutcome::class)]
#[CoversClass(McpDecisionReason::class)]
#[Group('mcp_sentinel')]
final class McpDecisionTest extends UnitTestCase {

  /**
   * Every outcome serializes to its stable backed value.
   *
   * @param \Drupal\mcp_sentinel\Value\McpDecision $decision
   *   The decision under test.
   * @param string $outcome
   *   Expected outcome code.
   * @param string $reason
   *   Expected reason code.
   * @param string[] $obligations
   *   Expected obligations list.
   *
   * @dataProvider outcomeSerializationProvider
   */
  #[DataProvider('outcomeSerializationProvider')]
  public function testEveryOutcomeSerializesStably(
    McpDecision $decision,
    string $outcome,
    string $reason,
    array $obligations,
  ): void {
    $this->assertSame($outcome, $decision->outcome()->value);
    $this->assertSame($reason, $decision->reason()->value);
    $this->assertSame($obligations, $decision->obligations());
    $this->assertSame(
      [
        'outcome' => $outcome,
        'reason' => $reason,
        'obligations' => $obligations,
      ],
      $decision->toArray(),
    );
    $this->assertSame(
      json_encode([
        'outcome' => $outcome,
        'reason' => $reason,
        'obligations' => $obligations,
      ], JSON_THROW_ON_ERROR),
      json_encode($decision->toArray(), JSON_THROW_ON_ERROR),
    );
  }

  /**
   * One fixture per outcome, including empty and non-empty obligations.
   *
   * @return array<string, array{0: \Drupal\mcp_sentinel\Value\McpDecision, 1: string, 2: string, 3: list<string>}>
   *   Cases keyed by outcome.
   */
  public static function outcomeSerializationProvider(): array {
    return [
      'deny' => [
        McpDecision::deny(McpDecisionReason::ApprovalRequired),
        'deny',
        'approval_required',
        [],
      ],
      'allow' => [
        McpDecision::allow(McpDecisionReason::NotGated),
        'allow',
        'not_gated',
        [],
      ],
      'require_approval' => [
        McpDecision::requireApproval(McpDecisionReason::AlwaysGated),
        'require_approval',
        'always_gated',
        [],
      ],
      'allow_with_obligations' => [
        McpDecision::allowWithObligations(
          McpDecisionReason::NotGated,
          ['log_receipt'],
        ),
        'allow_with_obligations',
        'not_gated',
        ['log_receipt'],
      ],
    ];
  }

  /**
   * Outcome and reason backed values are the public contract.
   */
  public function testOutcomeAndReasonCodesAreStable(): void {
    $this->assertSame(
      ['deny', 'allow', 'require_approval', 'allow_with_obligations'],
      array_map(
        static fn (McpDecisionOutcome $case): string => $case->value,
        McpDecisionOutcome::cases(),
      ),
    );
    $this->assertSame(
      [
        'always_gated',
        'approval_required',
        'not_gated',
        'manifest_missing',
        'manifest_invalid',
        'manifest_expired',
        'target_stale',
        'idempotency_replay',
        'self_approval',
        'approver_unauthorized',
        'superuser_refused',
        'manifest_unsealed',
      ],
      array_map(
        static fn (McpDecisionReason $case): string => $case->value,
        McpDecisionReason::cases(),
      ),
    );
  }

  /**
   * An unknown reason code cannot be constructed.
   */
  public function testUnknownReasonCannotBeConstructed(): void {
    $this->expectException(\ValueError::class);
    McpDecisionReason::from('not_a_reason');
  }

  /**
   * An unknown outcome code cannot be constructed.
   */
  public function testUnknownOutcomeCannotBeConstructed(): void {
    $this->expectException(\ValueError::class);
    McpDecisionOutcome::from('maybe');
  }

  /**
   * An unknown code is not coerced into a reason or outcome.
   */
  public function testUnknownReasonTryFromIsNull(): void {
    $this->assertNull(McpDecisionReason::tryFrom('not_a_reason'));
    $this->assertNull(McpDecisionOutcome::tryFrom('maybe'));
  }

  /**
   * Obligations are rejected on deny.
   */
  public function testObligationsRejectedOnDeny(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage(
      'Obligations are only valid on allow_with_obligations, not deny.',
    );
    $this->constructDecision(
      McpDecisionOutcome::Deny,
      McpDecisionReason::ApprovalRequired,
      ['log_receipt'],
    );
  }

  /**
   * Obligations are rejected on allow.
   */
  public function testObligationsRejectedOnAllow(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage(
      'Obligations are only valid on allow_with_obligations, not allow.',
    );
    $this->constructDecision(
      McpDecisionOutcome::Allow,
      McpDecisionReason::NotGated,
      ['log_receipt'],
    );
  }

  /**
   * Obligations are rejected on require_approval.
   */
  public function testObligationsRejectedOnRequireApproval(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage(
      'Obligations are only valid on allow_with_obligations, not require_approval.',
    );
    $this->constructDecision(
      McpDecisionOutcome::RequireApproval,
      McpDecisionReason::AlwaysGated,
      ['log_receipt'],
    );
  }

  /**
   * An allow-with-obligations decision refuses an empty list.
   */
  public function testAllowWithObligationsRequiresAtLeastOne(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage(
      'allow_with_obligations requires at least one obligation.',
    );
    McpDecision::allowWithObligations(McpDecisionReason::NotGated, []);
  }

  /**
   * A blank obligation string is not a code.
   */
  public function testBlankObligationIsRejected(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage(
      'Obligation at offset 0 must be a non-empty string.',
    );
    McpDecision::allowWithObligations(McpDecisionReason::NotGated, ['  ']);
  }

  /**
   * A non-string obligation is not a code.
   */
  public function testNonStringObligationIsRejected(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage(
      'Obligation at offset 1 must be a non-empty string.',
    );
    $this->constructDecision(
      McpDecisionOutcome::AllowWithObligations,
      McpDecisionReason::NotGated,
      ['log_receipt', 1],
    );
  }

  /**
   * Mutating the returned obligations list does not change the decision.
   */
  public function testObligationsListDoesNotLeakMutability(): void {
    $decision = McpDecision::allowWithObligations(
      McpDecisionReason::NotGated,
      ['log_receipt'],
    );
    $obligations = $decision->obligations();
    $obligations[] = 'tamper';
    $this->assertSame(['log_receipt'], $decision->obligations());
    $this->assertTrue($decision->hasObligations());
    $this->assertTrue($decision->isAllowed());
    $this->assertFalse($decision->isDenied());
    $this->assertFalse($decision->requiresApproval());
  }

  /**
   * Predicate helpers match the four outcomes.
   */
  public function testPredicatesFollowOutcome(): void {
    $deny = McpDecision::deny(McpDecisionReason::ApprovalRequired);
    $this->assertTrue($deny->isDenied());
    $this->assertFalse($deny->isAllowed());
    $this->assertFalse($deny->requiresApproval());
    $this->assertFalse($deny->hasObligations());

    $allow = McpDecision::allow(McpDecisionReason::NotGated);
    $this->assertFalse($allow->isDenied());
    $this->assertTrue($allow->isAllowed());
    $this->assertFalse($allow->requiresApproval());
    $this->assertFalse($allow->hasObligations());

    $held = McpDecision::requireApproval(McpDecisionReason::AlwaysGated);
    $this->assertFalse($held->isDenied());
    $this->assertFalse($held->isAllowed());
    $this->assertTrue($held->requiresApproval());
    $this->assertFalse($held->hasObligations());
  }

  /**
   * Invokes the private constructor so pairing invariants can be tested.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpDecisionOutcome $outcome
   *   Outcome.
   * @param \Drupal\mcp_sentinel\Enum\McpDecisionReason $reason
   *   Reason.
   * @param array $obligations
   *   Obligations to pair with the outcome.
   *
   * @return \Drupal\mcp_sentinel\Value\McpDecision
   *   The constructed decision.
   */
  private function constructDecision(
    McpDecisionOutcome $outcome,
    McpDecisionReason $reason,
    array $obligations,
  ): McpDecision {
    $constructor = new \ReflectionMethod(McpDecision::class, '__construct');
    $decision = (new \ReflectionClass(McpDecision::class))
      ->newInstanceWithoutConstructor();
    $constructor->invoke($decision, $outcome, $reason, $obligations);
    return $decision;
  }

}
