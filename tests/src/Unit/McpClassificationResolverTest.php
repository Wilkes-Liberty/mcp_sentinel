<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Unit tests for the classification label vocabulary and assignment lookups.
 *
 * Covers the site-defined ordered vocabulary, assignment specificity
 * (bundle beats type, field beats entity), the deny-more treatment of labels
 * outside the vocabulary, and the empty-map behaviour that lets slice A ship
 * dark (d.o #3616540 part 2).
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpClassificationResolver
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpClassificationResolver::class)]
#[Group('mcp_sentinel')]
final class McpClassificationResolverTest extends UnitTestCase {

  /**
   * Builds a resolver over the given settings values.
   *
   * @param array $settings
   *   Values for mcp_sentinel.settings.
   */
  private function resolver(array $settings): McpClassificationResolver {
    $configFactory = $this->getConfigFactoryStub(['mcp_sentinel.settings' => $settings]);
    $requestStack = new RequestStack();
    return new McpClassificationResolver(
      $configFactory,
      $requestStack,
      new Settings([]),
      new McpAuditLogger($configFactory, $requestStack, NULL),
    );
  }

  /**
   * Shorthand for a map row.
   */
  private static function row(string $type, string $label, string $bundle = '', string $field = ''): array {
    return ['entity_type' => $type, 'bundle' => $bundle, 'field' => $field, 'label' => $label];
  }

  /**
   * An absent or empty vocabulary falls back to the built-in default.
   */
  public function testVocabularyDefaultsWhenAbsent(): void {
    $this->assertSame(['public', 'internal', 'restricted'], $this->resolver([])->labels());
    $this->assertSame(['public', 'internal', 'restricted'], $this->resolver(['classification_labels' => []])->labels());
    $this->assertSame('public', $this->resolver([])->lowestLabel());
    $this->assertSame('restricted', $this->resolver([])->highestLabel());
  }

  /**
   * A site-defined vocabulary is honoured in order, blanks and repeats dropped.
   */
  public function testSiteDefinedVocabulary(): void {
    $resolver = $this->resolver(['classification_labels' => ['open', ' ', 'staff', 'open', 'secret']]);
    $this->assertSame(['open', 'staff', 'secret'], $resolver->labels());
    $this->assertSame(0, $resolver->rank('open'));
    $this->assertSame(2, $resolver->rank('secret'));
    $this->assertNull($resolver->rank('internal'), 'A label outside the vocabulary has no rank.');
  }

  /**
   * exceeds() is a strict comparison on vocabulary order; no ceiling = never.
   */
  public function testExceedsFollowsVocabularyOrder(): void {
    $resolver = $this->resolver([]);
    $this->assertFalse($resolver->exceeds('public', 'public'));
    $this->assertFalse($resolver->exceeds('internal', 'restricted'));
    $this->assertTrue($resolver->exceeds('restricted', 'internal'));
    $this->assertTrue($resolver->exceeds('internal', 'public'));
    $this->assertFalse($resolver->exceeds('restricted', NULL), 'No ceiling means nothing exceeds it.');
  }

  /**
   * Labels outside the vocabulary fail closed on both sides of the check.
   */
  public function testUnknownLabelsFailClosed(): void {
    $resolver = $this->resolver([]);
    // Data carrying an unknown label sits above the highest label.
    $this->assertTrue($resolver->exceeds('top-secret', 'restricted'));
    // A ceiling naming an unknown label behaves as the lowest label.
    $this->assertTrue($resolver->exceeds('internal', 'bogus'));
    $this->assertFalse($resolver->exceeds('public', 'bogus'));
  }

  /**
   * Unlabelled data is the lowest label; bundle rows beat type rows.
   */
  public function testEntityTypeAndBundleSpecificity(): void {
    $resolver = $this->resolver([
      'classification_map' => [
        self::row('node', 'internal'),
        self::row('node', 'restricted', 'memo'),
        self::row('user', 'restricted'),
      ],
    ]);
    $this->assertSame('public', $resolver->labelForEntityType('taxonomy_term'));
    $this->assertSame('public', $resolver->labelForEntityType('taxonomy_term', 'tags'));
    $this->assertSame('internal', $resolver->labelForEntityType('node'));
    $this->assertSame('internal', $resolver->labelForEntityType('node', 'article'));
    $this->assertSame('restricted', $resolver->labelForEntityType('node', 'memo'));
    $this->assertSame('restricted', $resolver->labelForEntityType('user', 'user'));
  }

  /**
   * Field rows override the entity label; bundle-scoped field rows win.
   */
  public function testFieldOverrides(): void {
    $resolver = $this->resolver([
      'classification_map' => [
        self::row('node', 'public'),
        self::row('node', 'internal', '', 'field_notes'),
        self::row('node', 'restricted', 'memo', 'field_notes'),
        self::row('node', 'restricted', 'memo'),
      ],
    ]);
    $this->assertSame('public', $resolver->labelForField('node', 'article', 'title'));
    $this->assertSame('internal', $resolver->labelForField('node', 'article', 'field_notes'));
    $this->assertSame('restricted', $resolver->labelForField('node', 'memo', 'field_notes'));
    // A field without its own row inherits the entity's (bundle) label.
    $this->assertSame('restricted', $resolver->labelForField('node', 'memo', 'title'));
    $this->assertSame('public', $resolver->labelForField('node', NULL, 'body'));
  }

  /**
   * The highest label of a type spans its type, bundle and field rows.
   */
  public function testHighestLabelForEntityType(): void {
    $resolver = $this->resolver([
      'classification_map' => [
        self::row('node', 'public'),
        self::row('node', 'internal', 'memo'),
        self::row('node', 'restricted', 'article', 'field_ssn'),
        self::row('media', 'internal'),
      ],
    ]);
    $this->assertSame('restricted', $resolver->highestLabelForEntityType('node'));
    $this->assertSame('internal', $resolver->highestLabelForEntityType('media'));
    $this->assertSame('public', $resolver->highestLabelForEntityType('taxonomy_term'));
  }

  /**
   * assignsAboveLowest() is the "has this site classified anything" question.
   */
  public function testAssignsAboveLowest(): void {
    $this->assertFalse($this->resolver([])->assignsAboveLowest());
    $this->assertFalse($this->resolver(['classification_map' => [self::row('node', 'public')]])->assignsAboveLowest());
    $this->assertTrue($this->resolver(['classification_map' => [self::row('node', 'internal')]])->assignsAboveLowest());
    // An unknown label counts as above the lowest — it fails closed.
    $this->assertTrue($this->resolver(['classification_map' => [self::row('node', 'bogus')]])->assignsAboveLowest());
  }

  /**
   * Malformed rows are ignored rather than crashing a read.
   */
  public function testMalformedRowsAreIgnored(): void {
    $resolver = $this->resolver([
      'classification_map' => [
        ['entity_type' => '', 'label' => 'restricted'],
        ['label' => 'restricted'],
        ['entity_type' => 'node'],
        'not-a-row',
        self::row('node', 'internal', 'memo'),
      ],
    ]);
    $this->assertSame('public', $resolver->labelForEntityType('node'));
    $this->assertSame('internal', $resolver->labelForEntityType('node', 'memo'));
  }

}
