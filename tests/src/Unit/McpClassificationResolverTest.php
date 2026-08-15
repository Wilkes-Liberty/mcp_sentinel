<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
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
  private function resolver(array $settings, ?RequestStack $requestStack = NULL): McpClassificationResolver {
    $configFactory = $this->getConfigFactoryStub(['mcp_sentinel.settings' => $settings]);
    $requestStack ??= new RequestStack();
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
   * A request stack holding one request for the given path.
   */
  private static function stack(string $path, array $headers = [], array $attributes = []): RequestStack {
    $request = Request::create($path);
    foreach ($headers as $name => $value) {
      $request->headers->set($name, $value);
    }
    foreach ($attributes as $name => $value) {
      $request->attributes->set($name, $value);
    }
    $stack = new RequestStack();
    $stack->push($request);
    return $stack;
  }

  /**
   * The current surface comes from the request path for the two HTTP APIs.
   */
  public function testCurrentSurfaceFromPath(): void {
    $this->assertSame(McpGovernedSurface::JsonApi, $this->resolver([], self::stack('/en/jsonapi/node/article'))->currentSurface());
    $this->assertSame(McpGovernedSurface::Graphql, $this->resolver([], self::stack('/graphql'))->currentSurface());
    $this->assertNull($this->resolver([], self::stack('/node/1'))->currentSurface());
    $this->assertNull($this->resolver([])->currentSurface(), 'No request, no surface.');
  }

  /**
   * Tool, context and drush call sites name their surface explicitly.
   */
  public function testCurrentSurfaceExplicit(): void {
    $tool = $this->resolver([], self::stack('/_mcp', [], [McpClassificationResolver::REQUEST_ATTRIBUTE_SURFACE => 'tool']));
    $this->assertSame(McpGovernedSurface::Tool, $tool->currentSurface());

    $context = $this->resolver([], self::stack('/drupal-mcp/context', [], ['_route' => 'mcp_sentinel.context']));
    $this->assertSame(McpGovernedSurface::Context, $context->currentSurface());

    // The CLI override wins over whatever request the stack holds.
    $drush = $this->resolver([], self::stack('/jsonapi/node/article'));
    $drush->setSurface(McpGovernedSurface::Drush);
    $this->assertSame(McpGovernedSurface::Drush, $drush->currentSurface());
    $drush->setSurface(NULL);
    $this->assertSame(McpGovernedSurface::JsonApi, $drush->currentSurface());
  }

  /**
   * The profile ceiling is per surface; an unknown surface takes the strictest.
   */
  public function testProfileCeilingPerSurface(): void {
    $resolver = $this->resolver([]);
    $profile = $this->profile(['jsonapi' => 'internal', 'tool' => 'restricted']);
    $this->assertSame('internal', $resolver->effectiveCeiling($profile, McpGovernedSurface::JsonApi));
    $this->assertSame('restricted', $resolver->effectiveCeiling($profile, McpGovernedSurface::Tool));
    $this->assertNull($resolver->effectiveCeiling($profile, McpGovernedSurface::Graphql), 'No key, no ceiling.');
    $this->assertSame('internal', $resolver->effectiveCeiling($profile, NULL), 'Unknown surface: the strictest configured ceiling.');
    $this->assertNull($resolver->effectiveCeiling($this->profile([]), NULL), 'No ceilings anywhere: nothing to apply.');
    // A ceiling naming an unknown label is the lowest label.
    $this->assertSame('public', $resolver->effectiveCeiling($this->profile(['jsonapi' => 'bogus']), McpGovernedSurface::JsonApi));
  }

  /**
   * A northbound declared ceiling can only lower the effective ceiling.
   */
  public function testDeclaredCeilingNarrowsOnly(): void {
    $profile = $this->profile(['jsonapi' => 'restricted']);
    $surface = McpGovernedSurface::JsonApi;

    $below = $this->resolver([], self::stack('/jsonapi/node/article', ['X-MCP-Declared-Ceiling' => 'internal']));
    $this->assertSame('internal', $below->effectiveCeiling($profile, $surface), 'Declaring below the profile ceiling lowers it.');
    $this->assertSame('internal', $below->declaredCeiling());

    $above = $this->resolver([], self::stack('/jsonapi/node/article', ['X-MCP-Declared-Ceiling' => 'restricted']));
    $this->assertSame('internal', $above->effectiveCeiling($this->profile(['jsonapi' => 'internal']), $surface), 'Declaring above the profile ceiling changes nothing.');

    $absent = $this->resolver([], self::stack('/jsonapi/node/article'));
    $this->assertSame('restricted', $absent->effectiveCeiling($profile, $surface));
    $this->assertNull($absent->declaredCeiling());

    $none = $this->resolver([], self::stack('/jsonapi/node/article', ['X-MCP-Declared-Ceiling' => 'internal']));
    $this->assertSame('internal', $none->effectiveCeiling($this->profile([]), $surface), 'A declaration narrows even a profile without a ceiling.');

    // Unknown or malformed declarations fail closed to the lowest label.
    $bogus = $this->resolver([], self::stack('/jsonapi/node/article', ['X-MCP-Declared-Ceiling' => 'top secret!']));
    $this->assertSame('public', $bogus->effectiveCeiling($profile, $surface));
    $long = $this->resolver([], self::stack('/jsonapi/node/article', ['X-MCP-Declared-Ceiling' => str_repeat('a', 200)]));
    $this->assertSame('public', $long->effectiveCeiling($profile, $surface));
  }

  /**
   * The declared destination is evidence-only and bounded.
   */
  public function testDeclaredDestinationIsBounded(): void {
    $this->assertNull($this->resolver([], self::stack('/jsonapi/x'))->declaredDestination());
    $ok = $this->resolver([], self::stack('/jsonapi/x', ['X-MCP-Declared-Destination' => 'tenant-a:crm.export']));
    $this->assertSame('tenant-a:crm.export', $ok->declaredDestination());
    $bad = $this->resolver([], self::stack('/jsonapi/x', ['X-MCP-Declared-Destination' => "evil\n" . str_repeat('x', 300)]));
    $this->assertNull($bad->declaredDestination(), 'A malformed declaration is not recorded verbatim.');
  }

  /**
   * denies() composes the label lookup with the effective ceiling.
   */
  public function testDenies(): void {
    $resolver = $this->resolver(['classification_map' => [self::row('node', 'restricted', 'memo')]], self::stack('/jsonapi/node/memo'));
    $internal = $this->profile(['jsonapi' => 'internal']);
    $restricted = $this->profile(['jsonapi' => 'restricted']);
    $this->assertTrue($resolver->denies($internal, McpGovernedSurface::JsonApi, 'restricted'));
    $this->assertFalse($resolver->denies($restricted, McpGovernedSurface::JsonApi, 'restricted'));
    $this->assertFalse($resolver->denies($internal, McpGovernedSurface::JsonApi, 'public'));
    $this->assertFalse($resolver->denies($this->profile([]), McpGovernedSurface::JsonApi, 'restricted'), 'Ships dark: no ceiling, no denial.');
  }

}
