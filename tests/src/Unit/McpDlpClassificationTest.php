<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpDlp;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Classification-aware, tighten-only DLP (d.o #3617061).
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpDlp
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpDlp::class)]
#[CoversClass(McpClassificationResolver::class)]
#[Group('mcp_sentinel')]
final class McpDlpClassificationTest extends UnitTestCase {

  /**
   * A DLP instance with one labelled custom pattern.
   *
   * @param string $mask_mode
   *   Mask mode: 'redact' or 'partial'.
   * @param string $classification
   *   Pattern classification label, or '' for mask-only.
   */
  private function dlp(string $mask_mode = 'partial', string $classification = 'restricted'): McpDlp {
    $pattern = [
      'label' => 'employee_id',
      'regex' => 'EMP-\d{6}',
      'mask' => '*',
    ];
    if ($classification !== '') {
      $pattern['classification'] = $classification;
    }
    return new McpDlp(TRUE, [$pattern], $mask_mode);
  }

  /**
   * A resolver over the default vocabulary, optionally with a current request.
   */
  private function resolver(?RequestStack $stack = NULL): McpClassificationResolver {
    $settings = ['classification_labels' => ['public', 'internal', 'restricted']];
    $configFactory = $this->getConfigFactoryStub(['mcp_sentinel.settings' => $settings]);
    $stack ??= new RequestStack();
    if ($stack->getCurrentRequest() === NULL) {
      $stack->push(Request::create('/graphql'));
    }
    return new McpClassificationResolver(
      $configFactory,
      $stack,
      new Settings([]),
      new McpAuditLogger($configFactory, $stack, NULL),
    );
  }

  /**
   * A profile mock carrying the given per-surface ceilings.
   *
   * @param array<string, string> $ceilings
   *   Surface value => label.
   */
  private function profile(array $ceilings): McpPolicyProfileInterface {
    $profile = $this->createMock(McpPolicyProfileInterface::class);
    $profile->method('id')->willReturn('p');
    $profile->method('getEgressCeilings')->willReturn($ceilings);
    $profile->method('getEgressCeiling')->willReturnCallback(
      static fn (McpGovernedSurface $s): ?string => $ceilings[$s->value] ?? NULL,
    );
    return $profile;
  }

  /**
   * Inspect reports a labelled hit and still masks.
   *
   * @covers ::inspect
   */
  public function testInspectReportsLabelledHit(): void {
    $result = $this->dlp()->inspect('id EMP-123456 ok');
    $this->assertSame(['restricted'], $result->classifications());
    $this->assertStringNotContainsString('EMP-123456', $result->value());
    $this->assertFalse($result->isDenied());
  }

  /**
   * A pattern without classification is mask-only.
   *
   * @covers ::inspect
   */
  public function testAbsentClassificationIsMaskOnly(): void {
    $result = $this->dlp('redact', '')->inspect('EMP-123456');
    $this->assertSame([], $result->classifications());
    $this->assertSame('[REDACTED]', $result->value());
  }

  /**
   * A hit whose label exceeds the ceiling fully redacts, even in partial mode.
   *
   * @covers ::applyForEgress
   */
  public function testHitTightensValueWhenItExceedsCeiling(): void {
    $resolver = $this->resolver();
    $result = $this->dlp()->applyForEgress('EMP-123456', 'public', $resolver);
    $this->assertTrue($result->isDenied());
    $this->assertSame('restricted', $result->deniedLabel());
    $this->assertSame('[REDACTED]', $result->value());
    $this->assertStringNotContainsString('3456', $result->value());
  }

  /**
   * A hit at the ceiling is masked, not refused.
   *
   * @covers ::applyForEgress
   */
  public function testHitAtCeilingIsMaskedNotRefused(): void {
    $resolver = $this->resolver();
    $result = $this->dlp()->applyForEgress('EMP-123456', 'restricted', $resolver);
    $this->assertFalse($result->isDenied());
    $this->assertStringEndsWith('3456', $result->value());
    $this->assertStringStartsWith('*', $result->value());
  }

  /**
   * A restricted hit cannot raise a public ceiling.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpClassificationResolver::observeDetectorHit
   */
  public function testHitCannotWidenCeiling(): void {
    $resolver = $this->resolver();
    $profile = $this->profile(['graphql' => 'public']);
    $this->assertSame('public', $resolver->effectiveCeiling($profile, McpGovernedSurface::Graphql));
    $this->dlp()->applyForEgress('EMP-123456', 'public', $resolver);
    $this->assertSame('restricted', $resolver->detectorCeiling());
    $this->assertSame('public', $resolver->effectiveCeiling($profile, McpGovernedSurface::Graphql), 'A restricted hit must not raise a public ceiling.');
  }

  /**
   * An internal hit lowers a restricted ceiling for the rest of the request.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpClassificationResolver::observeDetectorHit
   */
  public function testHitTightensRequestCeiling(): void {
    $resolver = $this->resolver();
    $profile = $this->profile(['graphql' => 'restricted']);
    $this->dlp('partial', 'internal')->applyForEgress('EMP-123456', 'restricted', $resolver);
    $this->assertSame('internal', $resolver->detectorCeiling());
    $this->assertSame('internal', $resolver->effectiveCeiling($profile, McpGovernedSurface::Graphql));
  }

  /**
   * A detector hit cannot invent a ceiling when none is in force.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpClassificationResolver::effectiveCeiling
   */
  public function testDetectorCannotInventCeiling(): void {
    $resolver = $this->resolver();
    $this->dlp()->applyForEgress('EMP-123456', NULL, $resolver);
    $this->assertSame('restricted', $resolver->detectorCeiling());
    $this->assertNull($resolver->effectiveCeiling($this->profile([]), McpGovernedSurface::Graphql));
  }

  /**
   * An unknown pattern label fail-closes as the lowest ceiling contribution.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpClassificationResolver::observeDetectorHit
   */
  public function testUnknownDetectorLabelIsLowestCeiling(): void {
    $resolver = $this->resolver();
    $resolver->observeDetectorHit('top-secret');
    $this->assertSame('public', $resolver->detectorCeiling());
    $profile = $this->profile(['graphql' => 'restricted']);
    $this->assertSame('public', $resolver->effectiveCeiling($profile, McpGovernedSurface::Graphql));
  }

  /**
   * ScanTree walks nested strings and later siblings see a tightened ceiling.
   *
   * @covers ::scanTree
   */
  public function testScanTreeLaterSiblingSeesTightenedCeiling(): void {
    $resolver = $this->resolver();
    $dlp = new McpDlp(TRUE, [
      [
        'label' => 'employee_id',
        'regex' => 'EMP-\d{6}',
        'mask' => '*',
        'classification' => 'internal',
      ],
      [
        'label' => 'ssn',
        'regex' => '\d{3}-\d{2}-\d{4}',
        'mask' => '*',
        'classification' => 'restricted',
      ],
    ], 'partial');
    $out = $dlp->scanTree([
      'first' => 'EMP-123456',
      'nested' => ['ssn' => '123-45-6789'],
    ], 'restricted', $resolver);
    $this->assertIsArray($out);
    $this->assertStringEndsWith('3456', (string) $out['first']);
    $this->assertSame('[REDACTED]', $out['nested']['ssn'], 'A later restricted hit must be refused after an internal hit tightened the ceiling.');
  }

  /**
   * Scan still returns only the string (back-compat).
   *
   * @covers ::scan
   */
  public function testScanStillReturnsString(): void {
    $this->assertSame('[REDACTED]', $this->dlp('redact')->scan('EMP-123456'));
  }

}
