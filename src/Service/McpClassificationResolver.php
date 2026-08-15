<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Resolves classification labels and per-surface egress ceilings.
 *
 * The source-side half of P4.8 (d.o #3616540 part 2). Two things are
 * configuration, not content inspection:
 *
 *  - Assignment (global, mcp_sentinel.settings:classification_map): facts
 *    about data. Rows label an entity type, optionally one bundle, optionally
 *    one field. Unlabelled data carries the lowest label of the site's
 *    ordered vocabulary (classification_labels), so an empty map labels
 *    nothing above the floor.
 *  - Ceilings (per profile, egress_ceilings): policy about principals. A
 *    "destination" is the pair (server-resolved profile, governed surface),
 *    and the ceiling is the highest label that pair may receive.
 *
 * Deny more, never less: a label outside the vocabulary counts as *above*
 * the highest label when it describes data and as the *lowest* label when it
 * names a ceiling. Hard P0.4 denies (entity-type deny lists, redacted
 * fields) are evaluated before any ceiling and always win.
 */
final class McpClassificationResolver {

  /**
   * The vocabulary used when a site has not named its own.
   */
  public const DEFAULT_LABELS = ['public', 'internal', 'restricted'];

  /**
   * The stable structured code carried by every classification refusal.
   */
  public const DENIAL_CODE = 'classification_egress_denied';

  /**
   * Request attribute through which a call site names its surface.
   *
   * Tool execution has no path of its own (the MCP transport is another
   * module's route), so the governed Tool base stamps the request when it
   * gates access; the same request object is what the Tool later executes
   * under. The context controller is identified by its route name.
   */
  public const REQUEST_ATTRIBUTE_SURFACE = '_mcp_sentinel_surface';

  /**
   * Northbound declared ceiling — the connector's narrow-only context.
   *
   * The wire contract for drupal-mcp-connector #179: a governed request may
   * declare a ceiling; the effective ceiling is min(profile, declared).
   * Declaring higher than the profile permits changes nothing.
   */
  public const HEADER_DECLARED_CEILING = 'X-MCP-Declared-Ceiling';

  /**
   * Northbound declared destination — recorded in evidence, never enforced.
   *
   * Attested destinations are the hosted residual (#177/#178); until then the
   * declaration is a bounded identifier the source writes into its evidence.
   */
  public const HEADER_DECLARED_DESTINATION = 'X-MCP-Declared-Destination';

  /**
   * Bound on caller-supplied declaration values before use or evidence.
   */
  private const DECLARATION_MAX_LENGTH = 128;

  /**
   * Characters a declaration may carry; anything else is malformed.
   */
  private const DECLARATION_PATTERN = '/^[A-Za-z0-9._:-]+$/';

  /**
   * An explicit surface set by a call site without a request (drush).
   */
  private ?McpGovernedSurface $explicitSurface = NULL;

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly RequestStack $requestStack,
    private readonly Settings $settings,
    private readonly McpAuditLogger $auditLogger,
  ) {}

  /**
   * The ordered vocabulary, lowest label first.
   *
   * @return string[]
   *   Non-empty, de-duplicated labels; the built-in default when the site has
   *   configured none.
   */
  public function labels(): array {
    $configured = $this->configFactory->get('mcp_sentinel.settings')->get('classification_labels');
    $labels = [];
    foreach (is_array($configured) ? $configured : [] as $label) {
      if (!is_string($label)) {
        continue;
      }
      $label = trim($label);
      if ($label !== '' && !in_array($label, $labels, TRUE)) {
        $labels[] = $label;
      }
    }
    return $labels === [] ? self::DEFAULT_LABELS : $labels;
  }

  /**
   * The lowest label — what unlabelled data carries.
   */
  public function lowestLabel(): string {
    return $this->labels()[0];
  }

  /**
   * The highest label in the vocabulary.
   */
  public function highestLabel(): string {
    $labels = $this->labels();
    return $labels[count($labels) - 1];
  }

  /**
   * The position of a label in the vocabulary, or NULL when it has none.
   */
  public function rank(string $label): ?int {
    $rank = array_search($label, $this->labels(), TRUE);
    return $rank === FALSE ? NULL : $rank;
  }

  /**
   * Whether data labelled $label may not leave through a ceiling of $ceiling.
   *
   * @param string $label
   *   The data's label. Unknown labels sit above the highest label.
   * @param string|null $ceiling
   *   The effective ceiling, or NULL for no ceiling. Unknown ceilings behave
   *   as the lowest label.
   */
  public function exceeds(string $label, ?string $ceiling): bool {
    if ($ceiling === NULL) {
      return FALSE;
    }
    $dataRank = $this->rank($label) ?? PHP_INT_MAX;
    $ceilingRank = $this->rank($ceiling) ?? 0;
    return $dataRank > $ceilingRank;
  }

  /**
   * The label assigned to an entity type, or one bundle of it.
   *
   * A bundle row beats a type row; nothing assigned means the lowest label.
   */
  public function labelForEntityType(string $entityTypeId, ?string $bundle = NULL): string {
    $rows = $this->rows();
    if ($bundle !== NULL && $bundle !== '') {
      $label = $rows[$entityTypeId][$bundle][''] ?? NULL;
      if ($label !== NULL) {
        return $label;
      }
    }
    return $rows[$entityTypeId][''][''] ?? $this->lowestLabel();
  }

  /**
   * The label assigned to one field, falling back to its entity's label.
   *
   * A bundle-scoped field row beats an any-bundle field row, which beats the
   * entity's own (bundle or type) label.
   */
  public function labelForField(string $entityTypeId, ?string $bundle, string $fieldName): string {
    $rows = $this->rows();
    if ($bundle !== NULL && $bundle !== '') {
      $label = $rows[$entityTypeId][$bundle][$fieldName] ?? NULL;
      if ($label !== NULL) {
        return $label;
      }
    }
    return $rows[$entityTypeId][''][$fieldName] ?? $this->labelForEntityType($entityTypeId, $bundle);
  }

  /**
   * The label of a concrete entity (its bundle row, else its type row).
   */
  public function labelForEntity(EntityInterface $entity): string {
    return $this->labelForEntityType($entity->getEntityTypeId(), $entity->bundle());
  }

  /**
   * The highest label any row assigns within an entity type.
   *
   * For seams that cannot see bundles — raw SQL over a type's tables, JSON:API
   * filter access — the whole type is judged by its most sensitive row.
   */
  public function highestLabelForEntityType(string $entityTypeId): string {
    $highest = $this->lowestLabel();
    $highestRank = 0;
    foreach ($this->rows()[$entityTypeId] ?? [] as $fields) {
      foreach ($fields as $label) {
        $rank = $this->rank($label) ?? PHP_INT_MAX;
        if ($rank > $highestRank) {
          $highestRank = $rank;
          $highest = $label;
        }
      }
    }
    return $highest;
  }

  /**
   * Whether the site has labelled anything above the lowest label.
   *
   * The half of the status-report question that concerns data: a site that
   * assigns nothing above the floor has no classification to enforce.
   */
  public function assignsAboveLowest(): bool {
    foreach ($this->rows() as $bundles) {
      foreach ($bundles as $fields) {
        foreach ($fields as $label) {
          if (($this->rank($label) ?? PHP_INT_MAX) > 0) {
            return TRUE;
          }
        }
      }
    }
    return FALSE;
  }

  /**
   * Names the surface explicitly for call sites that have no request.
   *
   * The governed drush SQL command runs on the CLI, where there is nothing to
   * read a surface from; it sets Drush here before checking a statement.
   * NULL clears the override so request-derived detection resumes.
   */
  public function setSurface(?McpGovernedSurface $surface): void {
    $this->explicitSurface = $surface;
  }

  /**
   * The governed surface the current request is on, or NULL when unknown.
   *
   * Resolution order: an explicit CLI override; the request attribute stamped
   * by a Tool call site; the context route; the two path-addressable HTTP
   * APIs. NULL means a governed principal reached a read outside every
   * governed surface — the ceiling logic then applies the strictest configured
   * ceiling rather than none (deny more, never less).
   */
  public function currentSurface(): ?McpGovernedSurface {
    if ($this->explicitSurface !== NULL) {
      return $this->explicitSurface;
    }
    $request = $this->requestStack->getCurrentRequest();
    if ($request === NULL) {
      return NULL;
    }
    $stamped = $request->attributes->get(self::REQUEST_ATTRIBUTE_SURFACE);
    if (is_string($stamped)) {
      $surface = McpGovernedSurface::tryFrom($stamped);
      if ($surface !== NULL) {
        return $surface;
      }
    }
    if ($request->attributes->get('_route') === 'mcp_sentinel.context') {
      return McpGovernedSurface::Context;
    }
    return McpGovernedSurface::fromPath($request->getPathInfo());
  }

  /**
   * The ceiling in force for a profile on a surface, after narrowing.
   *
   * min(profile ceiling, declared ceiling). A profile ceiling naming an
   * unknown label is the lowest label; an unknown surface takes the strictest
   * ceiling the profile configures anywhere; a profile with no ceilings and no
   * declaration has none — that is how the mechanism ships dark.
   *
   * @return string|null
   *   The effective ceiling label, or NULL for no ceiling.
   */
  public function effectiveCeiling(McpPolicyProfileInterface $profile, ?McpGovernedSurface $surface): ?string {
    $ceiling = $this->profileCeiling($profile, $surface);
    $declared = $this->declaredCeiling();
    if ($declared === NULL) {
      return $ceiling;
    }
    if ($ceiling === NULL) {
      return $declared;
    }
    return ($this->rank($declared) ?? 0) < ($this->rank($ceiling) ?? 0) ? $declared : $ceiling;
  }

  /**
   * The northbound declared ceiling, normalized, or NULL when none was sent.
   *
   * A declaration outside the vocabulary — or malformed — is the lowest label:
   * the caller asked to narrow and cannot be granted more than the floor.
   */
  public function declaredCeiling(): ?string {
    $raw = $this->rawDeclaration(self::HEADER_DECLARED_CEILING);
    if ($raw === NULL) {
      return NULL;
    }
    return $this->isWellFormedDeclaration($raw) && $this->rank($raw) !== NULL
      ? $raw
      : $this->lowestLabel();
  }

  /**
   * The northbound declared destination, bounded, or NULL when none/malformed.
   *
   * Recorded in evidence only. A malformed value is dropped rather than
   * written into the audit chain verbatim.
   */
  public function declaredDestination(): ?string {
    $raw = $this->rawDeclaration(self::HEADER_DECLARED_DESTINATION);
    return $raw !== NULL && $this->isWellFormedDeclaration($raw) ? $raw : NULL;
  }

  /**
   * Whether data carrying $label may not leave through (profile, surface).
   */
  public function denies(McpPolicyProfileInterface $profile, ?McpGovernedSurface $surface, string $label): bool {
    return $this->exceeds($label, $this->effectiveCeiling($profile, $surface));
  }

  /**
   * The profile's own ceiling for a surface (strictest when surface unknown).
   */
  private function profileCeiling(McpPolicyProfileInterface $profile, ?McpGovernedSurface $surface): ?string {
    if ($surface !== NULL) {
      $ceiling = $profile->getEgressCeiling($surface);
      return $ceiling === NULL ? NULL : $this->normalizeCeiling($ceiling);
    }
    $strictest = NULL;
    $strictestRank = PHP_INT_MAX;
    foreach ($profile->getEgressCeilings() as $ceiling) {
      $normalized = $this->normalizeCeiling($ceiling);
      $rank = $this->rank($normalized) ?? 0;
      if ($rank < $strictestRank) {
        $strictestRank = $rank;
        $strictest = $normalized;
      }
    }
    return $strictest;
  }

  /**
   * A configured ceiling outside the vocabulary is the lowest label.
   */
  private function normalizeCeiling(string $ceiling): string {
    return $this->rank($ceiling) === NULL ? $this->lowestLabel() : $ceiling;
  }

  /**
   * The trimmed value of one declaration header, or NULL when absent/empty.
   */
  private function rawDeclaration(string $header): ?string {
    $request = $this->requestStack->getCurrentRequest();
    if (!$request instanceof Request || !$request->headers->has($header)) {
      return NULL;
    }
    $value = trim((string) $request->headers->get($header, ''));
    return $value === '' ? NULL : $value;
  }

  /**
   * Whether a caller-supplied declaration is within the accepted bound.
   */
  private function isWellFormedDeclaration(string $value): bool {
    return strlen($value) <= self::DECLARATION_MAX_LENGTH
      && preg_match(self::DECLARATION_PATTERN, $value) === 1;
  }

  /**
   * The assignment rows indexed as [entity_type][bundle][field] => label.
   *
   * Bundle '' means every bundle; field '' means the entity itself. Rows
   * without an entity type or label are ignored — a malformed row must never
   * turn a read into an exception.
   *
   * @return array<string, array<string, array<string, string>>>
   *   The index.
   */
  private function rows(): array {
    $configured = $this->configFactory->get('mcp_sentinel.settings')->get('classification_map');
    $index = [];
    foreach (is_array($configured) ? $configured : [] as $row) {
      if (!is_array($row)) {
        continue;
      }
      $type = trim((string) ($row['entity_type'] ?? ''));
      $label = trim((string) ($row['label'] ?? ''));
      if ($type === '' || $label === '') {
        continue;
      }
      $bundle = trim((string) ($row['bundle'] ?? ''));
      $field = trim((string) ($row['field'] ?? ''));
      $index[$type][$bundle][$field] = $label;
    }
    return $index;
  }

}
