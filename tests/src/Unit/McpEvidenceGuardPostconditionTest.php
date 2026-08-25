<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpEvidenceGuard;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Postcondition comparison on the existing evidence receipt.
 *
 * Slice 6 of #3616538: the correlated receipt records what actually
 * happened (target id/uuid/revision, outcome). A discrepancy against
 * the sealed expectation is detectable without a second evidence
 * subsystem.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpEvidenceGuard
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpEvidenceGuard::class)]
#[Group('mcp_sentinel')]
final class McpEvidenceGuardPostconditionTest extends UnitTestCase {

  /**
   * Matching expected and observed postconditions are not a discrepancy.
   *
   * @covers ::postconditionDiscrepancy
   */
  public function testMatchingPostconditionsHaveNoDiscrepancy(): void {
    $postconditions = [
      'target' => [
        'id' => '4',
        'uuid' => 'node-uuid',
        'revision' => '11',
      ],
      'outcome' => 'deleted',
      'exists' => FALSE,
    ];
    $this->assertNull(
      McpEvidenceGuard::postconditionDiscrepancy($postconditions, $postconditions),
    );
  }

  /**
   * Extra observed fields do not invent a discrepancy.
   *
   * @covers ::postconditionDiscrepancy
   */
  public function testObserverMayRecordMoreThanTheSealRequired(): void {
    $this->assertNull(McpEvidenceGuard::postconditionDiscrepancy(
      ['target' => ['uuid' => 'node-uuid']],
      [
        'target' => [
          'id' => '4',
          'uuid' => 'node-uuid',
          'revision' => '12',
        ],
        'outcome' => 'saved',
        'exists' => TRUE,
      ],
    ));
  }

  /**
   * Null or new identities are not compared.
   *
   * @covers ::postconditionDiscrepancy
   */
  public function testUnassignedIdentityIsNotCompared(): void {
    $this->assertNull(McpEvidenceGuard::postconditionDiscrepancy(
      ['target' => ['id' => NULL, 'uuid' => 'new-uuid']],
      ['target' => ['id' => '9', 'uuid' => 'new-uuid']],
    ));
    $this->assertNull(McpEvidenceGuard::postconditionDiscrepancy(
      ['target' => ['id' => '(new)', 'uuid' => 'new-uuid']],
      ['target' => ['id' => '9', 'uuid' => 'new-uuid']],
    ));
  }

  /**
   * A disagreeing field is the postcondition_discrepancy reason.
   *
   * @param array<string, mixed> $expected
   *   Sealed or intended postconditions.
   * @param array<string, mixed> $observed
   *   What the live target actually is.
   *
   * @dataProvider discrepancyProvider
   *
   * @covers ::postconditionDiscrepancy
   */
  #[DataProvider('discrepancyProvider')]
  public function testDisagreeingFieldIsDetectable(array $expected, array $observed): void {
    $this->assertSame(
      McpEvidenceGuard::REASON_POSTCONDITION_DISCREPANCY,
      McpEvidenceGuard::postconditionDiscrepancy($expected, $observed),
    );
  }

  /**
   * Independent expected/observed pairs that must disagree.
   *
   * @return array<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
   *   Cases keyed by which field disagrees.
   */
  public static function discrepancyProvider(): array {
    $base = [
      'target' => [
        'id' => '4',
        'uuid' => 'node-uuid',
        'revision' => '11',
      ],
      'outcome' => 'deleted',
      'exists' => FALSE,
    ];
    return [
      'uuid' => [
        $base,
        [
          'target' => [
            'id' => '4',
            'uuid' => 'other-uuid',
            'revision' => '11',
          ],
          'outcome' => 'deleted',
          'exists' => FALSE,
        ],
      ],
      'id' => [
        $base,
        [
          'target' => [
            'id' => '99',
            'uuid' => 'node-uuid',
            'revision' => '11',
          ],
          'outcome' => 'deleted',
          'exists' => FALSE,
        ],
      ],
      'revision' => [
        $base,
        [
          'target' => [
            'id' => '4',
            'uuid' => 'node-uuid',
            'revision' => '12',
          ],
          'outcome' => 'deleted',
          'exists' => FALSE,
        ],
      ],
      'outcome' => [
        $base,
        [
          'target' => $base['target'],
          'outcome' => 'present',
          'exists' => FALSE,
        ],
      ],
      'exists' => [
        $base,
        [
          'target' => $base['target'],
          'outcome' => 'deleted',
          'exists' => TRUE,
        ],
      ],
    ];
  }

}
