<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
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
   * Cache contexts every ceiling-dependent access result must carry.
   *
   * The decision varies by surface (route) and by the caller's declared
   * ceiling; without these a body computed for one surface or one
   * declaration could be re-served for another.
   */
  public const CACHE_CONTEXTS = ['route', 'headers:' . self::HEADER_DECLARED_CEILING];

  /**
   * Bound on the per-request evidence de-duplication set.
   *
   * A long-lived STDIO transport is one request for many calls; the set must
   * not grow without limit there.
   */
  private const EVIDENCE_DEDUPE_CAP = 256;

  /**
   * An explicit surface set by a call site without a request (drush).
   */
  private ?McpGovernedSurface $explicitSurface = NULL;

  /**
   * Evidence subjects already recorded for the current request.
   *
   * @var array<string, true>
   */
  private array $recorded = [];

  /**
   * The request the de-duplication set belongs to (spl_object_id), or 0.
   */
  private int $recordedFor = 0;

  /**
   * Tighten-only ceiling contributed by DLP hits on the current request.
   *
   * A labelled detector hit may lower this, and may never raise it. NULL
   * means no detector has spoken; a detector cannot invent a ceiling when
   * the profile and the caller declared none (the mechanism stays dark).
   */
  private ?string $detectorCeiling = NULL;

  /**
   * The request the detector ceiling belongs to (spl_object_id), or 0.
   */
  private int $detectorFor = 0;

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
      if (!is_scalar($label)) {
        continue;
      }
      $label = trim((string) $label);
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
   * The highest label any entity-level row (type or bundle) assigns to a type.
   *
   * Field rows are excluded: they govern column references, not the table.
   * Raw SQL cannot see bundles, so one restricted bundle puts the whole
   * type's tables above a lower ceiling.
   */
  public function highestEntityLabelForEntityType(string $entityTypeId): string {
    $highest = $this->lowestLabel();
    $highestRank = 0;
    foreach ($this->rows()[$entityTypeId] ?? [] as $fields) {
      $label = $fields[''] ?? NULL;
      if ($label === NULL) {
        continue;
      }
      $rank = $this->rank($label) ?? PHP_INT_MAX;
      if ($rank > $highestRank) {
        $highestRank = $rank;
        $highest = $label;
      }
    }
    return $highest;
  }

  /**
   * Field names of a type that any row labels above a ceiling.
   *
   * @return array<string, string>
   *   Field name => the offending label (the highest, when several rows).
   */
  public function fieldsAboveCeiling(string $entityTypeId, string $ceiling): array {
    $fields = [];
    foreach ($this->rows()[$entityTypeId] ?? [] as $byField) {
      foreach ($byField as $field => $label) {
        if ($field === '' || !$this->exceeds($label, $ceiling)) {
          continue;
        }
        $current = $fields[$field] ?? NULL;
        if ($current === NULL || ($this->rank($label) ?? PHP_INT_MAX) > ($this->rank($current) ?? PHP_INT_MAX)) {
          $fields[$field] = $label;
        }
      }
    }
    return $fields;
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
   * The minimum of the profile ceiling, the declared ceiling, and any
   * detector hits recorded on this request. A profile ceiling naming an
   * unknown label is the lowest label; an unknown surface takes the
   * strictest ceiling the profile configures anywhere; a profile with no
   * ceilings and no declaration has none — that is how the mechanism ships
   * dark. A detector hit cannot invent a ceiling when none is in force.
   *
   * @return string|null
   *   The effective ceiling label, or NULL for no ceiling.
   */
  public function effectiveCeiling(McpPolicyProfileInterface $profile, ?McpGovernedSurface $surface): ?string {
    $ceiling = $this->profileCeiling($profile, $surface);
    $declared = $this->declaredCeiling();
    if ($declared !== NULL) {
      $ceiling = $ceiling === NULL
        ? $declared
        : (($this->rank($declared) ?? 0) < ($this->rank($ceiling) ?? 0) ? $declared : $ceiling);
    }
    $detector = $this->detectorCeiling();
    if ($detector === NULL || $ceiling === NULL) {
      // No detector, or nothing in force to tighten: stay dark.
      return $ceiling;
    }
    return ($this->rank($detector) ?? 0) < ($this->rank($ceiling) ?? 0) ? $detector : $ceiling;
  }

  /**
   * Records a DLP hit label as a tighten-only ceiling contribution.
   *
   * The hit may lower the request-scoped detector ceiling and may never
   * raise it. A label outside the vocabulary behaves as the lowest label
   * (the same fail-closed rule as an unknown declared ceiling).
   *
   * @param string $label
   *   The classification label declared on the pattern that hit.
   */
  public function observeDetectorHit(string $label): void {
    $this->resetDetectorScope();
    $normalized = $this->rank($label) !== NULL ? $label : $this->lowestLabel();
    if ($this->detectorCeiling === NULL) {
      $this->detectorCeiling = $normalized;
      return;
    }
    if (($this->rank($normalized) ?? 0) < ($this->rank($this->detectorCeiling) ?? 0)) {
      $this->detectorCeiling = $normalized;
    }
  }

  /**
   * The request-scoped detector ceiling, or NULL when no labelled hit fired.
   */
  public function detectorCeiling(): ?string {
    $this->resetDetectorScope();
    return $this->detectorCeiling;
  }

  /**
   * Drops detector state when the request changes.
   */
  private function resetDetectorScope(): void {
    $request = $this->requestStack->getCurrentRequest();
    $id = $request === NULL ? 0 : spl_object_id($request);
    if ($id !== $this->detectorFor) {
      $this->detectorCeiling = NULL;
      $this->detectorFor = $id;
    }
  }

  /**
   * The northbound declared ceiling, normalised, or NULL when none was sent.
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
   * Records one bounded classification_egress_denied evidence row.
   *
   * Names only labels, surface, profile, entity type/bundle/field and the
   * caller's declarations — never a value. One row per distinct subject per
   * request: a collection that omits fifty entities of one bundle is one
   * decision, not fifty rows.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The profile whose ceiling refused the read.
   * @param \Drupal\mcp_sentinel\Enum\McpGovernedSurface|null $surface
   *   The surface, or NULL when the read happened outside every surface.
   * @param string $entityTypeId
   *   The entity type of the refused subject.
   * @param string $bundle
   *   Its bundle, or '' when the subject is a whole type.
   * @param string $field
   *   The field name when a field was refused, or '' for the entity.
   * @param string $label
   *   The subject's classification label.
   * @param string $ceiling
   *   The effective ceiling that refused it.
   */
  public function evidence(
    McpPolicyProfileInterface $profile,
    ?McpGovernedSurface $surface,
    string $entityTypeId,
    string $bundle,
    string $field,
    string $label,
    string $ceiling,
  ): void {
    $request = $this->requestStack->getCurrentRequest();
    $requestId = $request === NULL ? 0 : spl_object_id($request);
    if ($requestId !== $this->recordedFor) {
      $this->recorded = [];
      $this->recordedFor = $requestId;
    }
    $surfaceValue = $surface === NULL ? 'unknown' : $surface->value;
    $key = implode("\0", [$surfaceValue, $profile->id(), $entityTypeId, $bundle, $field, $label, $ceiling]);
    if (isset($this->recorded[$key])) {
      return;
    }
    if (count($this->recorded) >= self::EVIDENCE_DEDUPE_CAP) {
      $this->recorded = [];
    }
    $this->recorded[$key] = TRUE;

    // entity_type and bundle are lifted into audit_chain's own columns; the
    // classification label is deliberately NOT keyed 'label', which the chain
    // would treat as an entity label.
    $this->auditLogger->log(self::DENIAL_CODE, [
      'reason' => self::DENIAL_CODE,
      'surface' => $surfaceValue,
      'profile' => $profile->id(),
      'entity_type' => $entityTypeId,
      'bundle' => $bundle,
      'field' => $field,
      'classification' => $label,
      'ceiling' => $ceiling,
      'declared_ceiling' => $this->declaredCeiling(),
      'declared_destination' => $this->declaredDestination(),
      'origin' => $this->origin(),
    ]);
  }

  /**
   * The classification label of the schema documents (context, site-context).
   *
   * Schema is metadata, not content, and is classified `internal` by default
   * (mcp_sentinel.settings:context_schema_label). A label outside the
   * vocabulary is judged as the highest label by exceeds().
   */
  public function schemaLabel(): string {
    $label = trim((string) ($this->configFactory->get('mcp_sentinel.settings')->get('context_schema_label') ?? ''));
    return $label === '' ? 'internal' : $label;
  }

  /**
   * The structured refusal every HTTP seam returns for a classification denial.
   *
   * One shape for the request seam and the response seam: a JSON:API error
   * document whose first error carries the stable code. Never cacheable — the
   * decision is per principal, per surface and per declaration.
   */
  public function refusalResponse(): JsonResponse {
    $refusal = new JsonResponse([
      'errors' => [
        [
          'status' => '403',
          'code' => self::DENIAL_CODE,
          'title' => 'Classification exceeds the MCP Sentinel egress ceiling',
          'detail' => 'The requested data carries a classification label above the ceiling this principal may receive on this surface.',
        ],
      ],
    ], 403);
    $refusal->setPrivate();
    $refusal->headers->set('Cache-Control', 'private, no-store');
    $refusal->headers->set('Content-Type', 'application/vnd.api+json');
    return $refusal;
  }

  /**
   * The origin label: site and environment identity, recorded not enforced.
   *
   * @return array{site: string, environment: string}
   *   The site name and the environment declared in settings.php.
   */
  private function origin(): array {
    return [
      'site' => (string) ($this->configFactory->get('system.site')->get('name') ?? ''),
      'environment' => (string) ($this->settings->get('mcp_sentinel.environment') ?? ''),
    ];
  }

  /**
   * Whether a bundle may be described to a principal on a surface.
   *
   * Shared by the context endpoint and the site-context tool: an over-ceiling
   * bundle is omitted from the schema document, with one evidence row per
   * bundle per request. No profile or no ceiling describes everything.
   */
  public function describesBundle(?McpPolicyProfileInterface $profile, McpGovernedSurface $surface, ?string $ceiling, string $entityTypeId, string $bundle): bool {
    if ($profile === NULL || $ceiling === NULL) {
      return TRUE;
    }
    $label = $this->labelForEntityType($entityTypeId, $bundle);
    if (!$this->exceeds($label, $ceiling)) {
      return TRUE;
    }
    $this->evidence($profile, $surface, $entityTypeId, $bundle, '', $label, $ceiling);
    return FALSE;
  }

  /**
   * Whether the schema document may leave through (profile, surface).
   *
   * Refuses (with evidence) when the schema label exceeds the ceiling.
   */
  public function schemaDenied(McpPolicyProfileInterface $profile, McpGovernedSurface $surface, ?string $ceiling): bool {
    if ($ceiling === NULL) {
      return FALSE;
    }
    $label = $this->schemaLabel();
    if (!$this->exceeds($label, $ceiling)) {
      return FALSE;
    }
    $this->evidence($profile, $surface, 'schema', '', '', $label, $ceiling);
    return TRUE;
  }

  /**
   * A trimmed string from a hand-editable config value; '' for non-scalars.
   */
  private static function scalar(mixed $value): string {
    return is_scalar($value) ? trim((string) $value) : '';
  }

  /**
   * The profile's own ceiling for a surface (strictest when surface unknown).
   */
  private function profileCeiling(McpPolicyProfileInterface $profile, ?McpGovernedSurface $surface): ?string {
    if ($surface !== NULL) {
      $ceiling = $profile->getEgressCeiling($surface);
      return $ceiling === NULL ? NULL : $this->normaliseCeiling($ceiling);
    }
    $strictest = NULL;
    $strictestRank = PHP_INT_MAX;
    foreach ($profile->getEgressCeilings() as $ceiling) {
      $normalised = $this->normaliseCeiling($ceiling);
      $rank = $this->rank($normalised) ?? 0;
      if ($rank < $strictestRank) {
        $strictestRank = $rank;
        $strictest = $normalised;
      }
    }
    return $strictest;
  }

  /**
   * A configured ceiling outside the vocabulary is the lowest label.
   */
  private function normaliseCeiling(string $ceiling): string {
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
      $type = self::scalar($row['entity_type'] ?? '');
      $label = self::scalar($row['label'] ?? '');
      if ($type === '' || $label === '') {
        continue;
      }
      $index[$type][self::scalar($row['bundle'] ?? '')][self::scalar($row['field'] ?? '')] = $label;
    }
    return $index;
  }

}
