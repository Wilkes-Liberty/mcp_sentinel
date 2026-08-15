<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\mcp_sentinel\EventSubscriber\McpJsonApiPageLimitSubscriber;
use Drupal\Core\Extension\ModuleExtensionList;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Plugin\Validation\Constraint\McpDenyPublish;
use Drupal\mcp_sentinel\Value\McpInstallCheck;
use Drupal\mcp_sentinel\Value\McpInstallVerificationResult;
use Drupal\node\Entity\Node;
use Symfony\Component\Validator\ConstraintViolationListInterface;

/**
 * Answers whether THIS install carries the secure, tenant-neutral floor.
 *
 * Two halves, one evidence document:
 *
 *  - Posture (always): source contract, companions, keyed evidence, finite
 *    budgets, an enabled role-bound policy, trust-role separation, no
 *    development fallback, tenant neutrality, classification labels.
 *  - Hostile input (`$live = TRUE`): an allowed draft, a denied publication,
 *    a mass read, a configuration change, a live-content edit. None of these
 *    persist. Write gates are decided through the same access checker,
 *    validate() constraint and unmoderated-redirect classifier the runtime
 *    uses. A process-scoped OAuth-channel flag lets validate() run from
 *    Drush; it is always cleared.
 *
 * Two rules shape every check:
 *
 *  - A check that cannot run is `skipped`, never `pass`.
 *  - Nothing secret reaches the result.
 */
final class McpInstallVerifier {

  /**
   * Posture checks, in report order.
   */
  public const POSTURE_CHECKS = [
    'source_contract',
    'companions',
    'keyed_evidence',
    'finite_budgets',
    'active_policy',
    'trust_role_separation',
    'no_dev_fallback',
    'tenant_neutrality',
    'classification_posture',
  ];

  /**
   * Hostile-input checks, in report order. Opt-in via the live flag.
   */
  public const HOSTILE_CHECKS = [
    'probe_allowed_draft',
    'probe_denied_publication',
    'probe_mass_read',
    'probe_config_change',
    'probe_live_content_edit',
  ];

  /**
   * A page size no governed profile should serve in one response.
   */
  public const MASS_READ_LIMIT = 5000;

  /**
   * Hostname suffixes reserved for documentation and testing (RFC 2606/6761).
   */
  private const RESERVED_SUFFIXES = [
    '.example.com',
    '.example.org',
    '.example.net',
    '.example',
    '.test',
    '.invalid',
    '.localhost',
  ];

  /**
   * Exact hostnames that are reserved, or public project infrastructure.
   */
  private const RESERVED_HOSTS = [
    'example.com',
    'example.org',
    'example.net',
    'localhost',
    '127.0.0.1',
    '::1',
    'www.drupal.org',
    'drupal.org',
  ];

  /**
   * Named residuals: properties this stack manages rather than solves.
   */
  public const RESIDUALS = [
    [
      'id' => 'prompt_injection',
      'status' => 'managed',
      'detail' => 'Prompt injection is not solved by this module. Instruction-shaped content reaching an agent through governed reads can still attempt to redirect it. What the stack constrains is the blast radius: least-privilege scopes, per-role policy, entity and field denies, classification egress ceilings, finite read budgets, no agent publication authority, and an audit trail of every governed action. Treat model output as untrusted input to any subsequent step.',
    ],
    [
      'id' => 'operator_trust',
      'status' => 'managed',
      'detail' => 'An operator who can run Drush or hold client secrets can act with the agent\'s authority. Secret custody, rotation and revocation stay the deploying organisation\'s responsibility; this verifier never prints a secret.',
    ],
  ];

  /**
   * Companion modules the source contract requires.
   */
  private const REQUIRED_COMPANIONS = [
    'audit_chain',
    'mcp_sentinel_server',
    'mcp_server_tool_bridge',
    'mcp_server_oauth',
  ];

  /**
   * Constructs the verifier.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly ModuleExtensionList $moduleExtensionList,
    private readonly McpGovernanceReadiness $governanceReadiness,
    private readonly McpRoleAssertions $roleAssertions,
    private readonly McpReadBudgetResolver $readBudgets,
    private readonly McpEvidenceGuard $evidenceGuard,
    private readonly McpClassificationResolver $classification,
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpAccessChecker $accessChecker,
    private readonly McpOauthContext $oauthContext,
    private readonly McpUnmoderatedForwardRevision $unmoderatedRedirect,
    private readonly AccountProxyInterface $currentUser,
    private readonly TimeInterface $time,
    private readonly McpJsonApiPageLimitSubscriber $pageLimitSubscriber,
    private readonly McpAuditLogger $auditLogger,
    private readonly Connection $database,
    private readonly ?ModerationInformationInterface $moderationInformation = NULL,
  ) {}

  /**
   * Verifies the current install.
   *
   * @param bool $live
   *   TRUE to also run the hostile-input probes.
   * @param string|null $contentTarget
   *   Optional UUID of an existing node for the live-content-edit probe.
   * @param string|null $bundle
   *   Optional node type for in-memory draft/publish probes.
   *
   * @return \Drupal\mcp_sentinel\Value\McpInstallVerificationResult
   *   The evidence document. Never contains secrets.
   */
  public function verify(
    bool $live = FALSE,
    ?string $contentTarget = NULL,
    ?string $bundle = NULL,
  ): McpInstallVerificationResult {
    $profile = $this->productionProfile();
    $resolvedBundle = $this->resolveBundle($bundle);
    $checks = [];
    foreach (self::POSTURE_CHECKS as $id) {
      $checks[] = $this->record($this->runCheck($id, $profile, $resolvedBundle, $contentTarget));
    }
    if ($live) {
      foreach (self::HOSTILE_CHECKS as $id) {
        $checks[] = $this->record($this->runCheck($id, $profile, $resolvedBundle, $contentTarget));
      }
    }

    $info = $this->moduleExtensionList->getExtensionInfo('mcp_sentinel');
    return new McpInstallVerificationResult(
      (string) ($info['version'] ?? 'dev'),
      \Drupal::VERSION,
      $this->configDigest(),
      $live ? 'live' : 'posture',
      $checks,
      self::RESIDUALS,
      gmdate('c', $this->time->getRequestTime()),
    );
  }

  /**
   * Runs one named check.
   */
  private function runCheck(
    string $id,
    ?McpPolicyProfileInterface $profile,
    ?string $bundle,
    ?string $contentTarget,
  ): McpInstallCheck {
    return match ($id) {
      'source_contract' => $this->checkSourceContract(),
      'companions' => $this->checkCompanions(),
      'keyed_evidence' => $this->checkKeyedEvidence(),
      'finite_budgets' => $this->checkFiniteBudgets(),
      'active_policy' => $this->checkActivePolicy(),
      'trust_role_separation' => $this->checkTrustRoleSeparation(),
      'no_dev_fallback' => $this->checkNoDevFallback(),
      'tenant_neutrality' => $this->checkTenantNeutrality(),
      'classification_posture' => $this->checkClassificationPosture(),
      'probe_allowed_draft' => $this->probeAllowedDraft($profile, $bundle),
      'probe_denied_publication' => $this->probeDeniedPublication($profile, $bundle),
      'probe_mass_read' => $this->probeMassRead($profile),
      'probe_config_change' => $this->probeConfigChange($profile),
      'probe_live_content_edit' => $this->probeLiveContentEdit($profile, $contentTarget),
      default => McpInstallCheck::fail($id, $id, ['unknown check.']),
    };
  }

  /**
   * Appends an install_verify audit row and copies its id onto the check.
   *
   * Only an install_verify row written after this call is attached. A
   * no-op log() (audit off) or a concurrent other-operation row is not
   * claimed as this check's evidence.
   */
  private function record(McpInstallCheck $check): McpInstallCheck {
    $before = $this->watermarkId();
    try {
      $this->auditLogger->log('install_verify', [
        'check' => $check->id(),
        'status' => $check->status(),
      ]);
    }
    catch (\Throwable) {
      return $check;
    }
    $id = $this->latestInstallVerifyId($before);
    if ($id === NULL) {
      return $check;
    }
    return new McpInstallCheck(
      $check->id(),
      $check->title(),
      $check->status(),
      $check->findings(),
      [$id],
      $check->observed(),
    );
  }

  /**
   * Highest audit-chain id before this check logs, any operation.
   */
  private function watermarkId(): ?string {
    return $this->latestRowId(FALSE, NULL);
  }

  /**
   * Newest install_verify row written after $after.
   */
  private function latestInstallVerifyId(?string $after): ?string {
    return $this->latestRowId(TRUE, $after);
  }

  /**
   * Newest matching audit-chain id.
   */
  private function latestRowId(bool $installVerifyOnly, ?string $after): ?string {
    try {
      $query = $this->database->select('audit_chain_log', 'l')
        ->fields('l', ['id'])
        ->orderBy('id', 'DESC')
        ->range(0, 1);
      if ($installVerifyOnly) {
        $query->condition('l.operation', 'install_verify');
      }
      if ($after !== NULL) {
        $query->condition('l.id', $after, '>');
      }
      $id = $query->execute()?->fetchField();
    }
    catch (\Throwable) {
      return NULL;
    }
    return $id !== FALSE && $id !== NULL ? (string) $id : NULL;
  }

  /**
   * Whether a hostname is safe to ship: reserved, loopback, or project infra.
   *
   * @param string $host
   *   Hostname, without scheme or port.
   *
   * @return bool
   *   TRUE when the host is documentation-reserved or public project infra.
   */
  public static function isNeutralHost(string $host): bool {
    $h = strtolower($host);
    $h = str_replace(['[', ']'], '', $h);
    if ($h === '') {
      return FALSE;
    }
    if (in_array($h, self::RESERVED_HOSTS, TRUE)) {
      return TRUE;
    }
    if (preg_match('/^127\.\d+\.\d+\.\d+$/', $h) === 1) {
      return TRUE;
    }
    foreach (self::RESERVED_SUFFIXES as $suffix) {
      if (str_ends_with($h, $suffix)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Findings for tenant leaks in shipped YAML under a directory.
   *
   * Accepts either the module root (scans config/install) or a flat
   * directory of YAML files, so CI and the unit tests share one scanner.
   *
   * @param string $directory
   *   Module root or a directory of YAML files.
   *
   * @return string[]
   *   Findings. Empty when the files are tenant-neutral.
   */
  public static function inspectShippedInstall(string $directory): array {
    $scan = $directory;
    if (is_dir($directory . '/config/install')) {
      $scan = $directory . '/config/install';
    }
    $files = glob($scan . '/*.yml') ?: [];
    $findings = [];
    foreach ($files as $file) {
      $text = (string) file_get_contents($file);
      $rel = basename($file);
      $findings = array_merge($findings, self::findingsInText($rel, $text));
    }
    return $findings;
  }

  /**
   * Source-governance contract (same typed result the runtime uses).
   */
  private function checkSourceContract(): McpInstallCheck {
    $title = 'The source-governance contract is ready';
    $contract = $this->governanceReadiness->contractStatus();
    if ($contract->isReady()) {
      return McpInstallCheck::pass('source_contract', $title);
    }
    $reason = $contract->reason();
    return McpInstallCheck::fail('source_contract', $title, [
      $reason !== NULL
        ? 'source contract is not ready: ' . $reason->value
        : 'source contract is not ready.',
    ]);
  }

  /**
   * Required companion modules are present.
   */
  private function checkCompanions(): McpInstallCheck {
    $title = 'Required companion modules are enabled';
    $missing = [];
    foreach (self::REQUIRED_COMPANIONS as $name) {
      if (!$this->moduleHandler->moduleExists($name)) {
        $missing[] = $name;
      }
    }
    if ($missing === []) {
      return McpInstallCheck::pass('companions', $title);
    }
    return McpInstallCheck::fail('companions', $title, [
      'missing companion module(s): ' . implode(', ', $missing),
    ]);
  }

  /**
   * The audit chain's signing key resolves.
   */
  private function checkKeyedEvidence(): McpInstallCheck {
    $title = 'Keyed evidence can be written';
    $settings = $this->configFactory->get('mcp_sentinel.settings');
    if (!(bool) $settings->get('audit_enabled')) {
      return McpInstallCheck::fail('keyed_evidence', $title, [
        'audit_enabled is off; refusals would not be recorded.',
      ]);
    }
    if (!$this->moduleHandler->moduleExists('audit_chain')) {
      return McpInstallCheck::fail('keyed_evidence', $title, [
        'audit_chain is not enabled.',
      ]);
    }
    if (!$this->evidenceGuard->signingKeyIsResolved()) {
      return McpInstallCheck::fail('keyed_evidence', $title, [
        'the audit-chain signing key does not resolve to usable material.',
      ]);
    }
    return McpInstallCheck::pass('keyed_evidence', $title);
  }

  /**
   * Finite read budgets are required and every profile resolves finite.
   */
  private function checkFiniteBudgets(): McpInstallCheck {
    $title = 'Read budgets are finite';
    if (!$this->readBudgets->finiteBudgetsRequired()) {
      return McpInstallCheck::fail('finite_budgets', $title, [
        'require_finite_read_budgets is off; mass reads are unbounded.',
      ]);
    }
    $findings = [];
    foreach ($this->enabledProfiles() as $profile) {
      $cap = $this->readBudgets->effectiveResultCap($profile);
      if ($cap <= 0) {
        $findings[] = sprintf(
          'profile %s resolves an unlimited result cap.',
          $profile->id(),
        );
      }
    }
    if ($findings !== []) {
      return McpInstallCheck::fail('finite_budgets', $title, $findings);
    }
    return McpInstallCheck::pass('finite_budgets', $title);
  }

  /**
   * An enabled, role-bound profile exists. A role-less default is not policy.
   */
  private function checkActivePolicy(): McpInstallCheck {
    $title = 'An enabled, role-bound policy is active';
    $bound = [];
    foreach ($this->enabledProfiles() as $profile) {
      if ($profile->getRoles() !== []) {
        $bound[] = $profile->id();
      }
    }
    if ($bound === []) {
      return McpInstallCheck::fail('active_policy', $title, [
        'no enabled policy profile binds a role; the role-less default is not production policy.',
      ]);
    }
    return McpInstallCheck::pass('active_policy', $title, [], [], [
      'profiles' => $bound,
    ]);
  }

  /**
   * Operator and public-agent trust roles are distinct.
   */
  private function checkTrustRoleSeparation(): McpInstallCheck {
    $title = 'Operator and public-agent trust roles are distinct';
    $findings = [];
    foreach ($this->policyResolver->getGovernedRoles() as $roleId) {
      if ($this->roleAssertions->isAdminRole($roleId)) {
        $findings[] = sprintf(
          'governed role %s is flagged is_admin; it holds every permission.',
          $roleId,
        );
      }
    }
    foreach ($this->roleAssertions->violations() as $violation) {
      $findings[] = $this->roleAssertions->describe($violation);
    }
    if ($findings !== []) {
      return McpInstallCheck::fail('trust_role_separation', $title, $findings);
    }
    $roles = $this->policyResolver->getGovernedRoles();
    if ($roles === []) {
      return McpInstallCheck::fail('trust_role_separation', $title, [
        'no governed role is configured, so operator and agent are not separable.',
      ]);
    }
    return McpInstallCheck::pass('trust_role_separation', $title);
  }

  /**
   * The development role fallback is off.
   */
  private function checkNoDevFallback(): McpInstallCheck {
    $title = 'Development role fallback is off';
    if ((bool) $this->configFactory->get('mcp_sentinel.settings')->get('governed_role_fallback')) {
      return McpInstallCheck::fail('no_dev_fallback', $title, [
        'governed_role_fallback is enabled; cookie sessions are treated as the agent channel.',
      ]);
    }
    return McpInstallCheck::pass('no_dev_fallback', $title);
  }

  /**
   * Shipped files and active config name no W&L host or shipped secret.
   */
  private function checkTenantNeutrality(): McpInstallCheck {
    $title = 'Shipped and active config name no tenant';
    $path = $this->moduleExtensionList->getPath('mcp_sentinel');
    $findings = self::inspectShippedInstall($path);
    $settings = $this->configFactory->get('mcp_sentinel.settings')->get() ?? [];
    foreach (self::strings($settings) as $item) {
      if (self::isWilkesLibertyIdentifier($item['value'])
        && !self::isPublicProjectReference($item['value'])) {
        $findings[] = sprintf(
          'active settings.%s names a W&L identifier.',
          $item['path'],
        );
      }
    }
    if ($findings !== []) {
      return McpInstallCheck::fail('tenant_neutrality', $title, $findings);
    }
    return McpInstallCheck::pass('tenant_neutrality', $title);
  }

  /**
   * Classification vocabulary exists and labels data above the floor.
   */
  private function checkClassificationPosture(): McpInstallCheck {
    $title = 'Classification labels data above the floor';
    $labels = $this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('classification_labels');
    if (!is_array($labels) || $labels === []) {
      return McpInstallCheck::fail('classification_posture', $title, [
        'classification_labels is empty.',
      ]);
    }
    if (!$this->classification->assignsAboveLowest()) {
      return McpInstallCheck::fail('classification_posture', $title, [
        'nothing is labelled above the lowest classification label.',
      ]);
    }
    return McpInstallCheck::pass('classification_posture', $title);
  }

  /**
   * Policy would allow an unpublished draft. Does not save.
   */
  private function probeAllowedDraft(
    ?McpPolicyProfileInterface $profile,
    ?string $bundle,
  ): McpInstallCheck {
    $title = 'An allowed draft would be accepted';
    if ($profile === NULL) {
      return McpInstallCheck::skipped('probe_allowed_draft', $title, 'no policy profile is available to evaluate a draft against.');
    }
    if (!$profile->allowsWrite()) {
      return McpInstallCheck::notApplicable('probe_allowed_draft', $title, 'this profile does not grant write, so there is no draft path to prove.');
    }
    if ($bundle === NULL) {
      return McpInstallCheck::skipped('probe_allowed_draft', $title, 'no node type exists, so a draft cannot be evaluated.');
    }
    $node = $this->unsavedNode($bundle, FALSE);
    $access = $this->accessChecker->checkEntityAccess($node, 'create', $profile);
    if ($access->isForbidden()) {
      $reason = $access instanceof AccessResultReasonInterface
        ? (string) $access->getReason()
        : '';
      return McpInstallCheck::fail('probe_allowed_draft', $title, [
        'create access is forbidden for an unpublished draft: ' . $reason,
      ]);
    }
    $violations = $this->asGovernedAgent(fn() => $node->validate());
    if ($violations === NULL) {
      return McpInstallCheck::skipped(
        'probe_allowed_draft',
        $title,
        'no governed account exists, so validate() would not see the agent channel.',
      );
    }
    if ($this->hasDenyPublishViolation($violations)) {
      return McpInstallCheck::fail('probe_allowed_draft', $title, [
        'validate() raised deny-publish on an unpublished draft.',
      ]);
    }
    return McpInstallCheck::pass('probe_allowed_draft', $title, [], [], [
      'bundle' => $bundle,
    ]);
  }

  /**
   * A go-live would be refused by the deny-publish constraint. Does not save.
   */
  private function probeDeniedPublication(
    ?McpPolicyProfileInterface $profile,
    ?string $bundle,
  ): McpInstallCheck {
    $title = 'A publication attempt is refused';
    if ($profile === NULL) {
      return McpInstallCheck::skipped('probe_denied_publication', $title, 'no policy profile is available to evaluate publication against.');
    }
    if (!$profile->deniesPublish()) {
      return McpInstallCheck::fail('probe_denied_publication', $title, [
        sprintf('profile %s has deny_publish off.', $profile->id()),
      ]);
    }
    if ($bundle === NULL) {
      return McpInstallCheck::skipped('probe_denied_publication', $title, 'no node type exists, so a publication attempt cannot be evaluated.');
    }
    $node = $this->unsavedNode($bundle, TRUE);
    if (!$this->applyGoLive($node)) {
      return McpInstallCheck::skipped(
        'probe_denied_publication',
        $title,
        'the bundle is moderated but has no published state, so a go-live cannot be evaluated.',
      );
    }
    $violations = $this->asGovernedAgent(
      fn() => $node->validate(),
    );
    if ($violations === NULL) {
      return McpInstallCheck::skipped(
        'probe_denied_publication',
        $title,
        'no governed account exists, so validate() would not see the agent channel.',
      );
    }
    if ($this->hasDenyPublishViolation($violations)) {
      return McpInstallCheck::pass('probe_denied_publication', $title, [], [], [
        'bundle' => $bundle,
      ]);
    }
    return McpInstallCheck::fail('probe_denied_publication', $title, [
      'validate() did not raise the deny-publish constraint for a go-live.',
    ]);
  }

  /**
   * A 5000-item page would be refused or bounded.
   */
  private function probeMassRead(?McpPolicyProfileInterface $profile): McpInstallCheck {
    $title = 'A ' . self::MASS_READ_LIMIT . '-item read is refused or bounded';
    if ($profile === NULL) {
      return McpInstallCheck::skipped('probe_mass_read', $title, 'no policy profile is available to resolve a read budget.');
    }
    if (!$this->readBudgets->finiteBudgetsRequired()) {
      return McpInstallCheck::fail('probe_mass_read', $title, [
        'require_finite_read_budgets is off; a mass read would not be bounded.',
      ]);
    }
    $cap = $this->readBudgets->effectiveResultCap($profile);
    if ($cap <= 0) {
      return McpInstallCheck::fail('probe_mass_read', $title, [
        'the effective result cap is unlimited.',
      ], [], ['cap' => $cap]);
    }
    if (!$this->pageLimitSubscriber->limitExceedsCap(self::MASS_READ_LIMIT, $profile)) {
      return McpInstallCheck::fail('probe_mass_read', $title, [
        sprintf('the JSON:API page-limit subscriber would not refuse a %d-item page (cap %d).', self::MASS_READ_LIMIT, $cap),
      ], [], ['cap' => $cap]);
    }
    return McpInstallCheck::pass('probe_mass_read', $title, [], [], ['cap' => $cap]);
  }

  /**
   * A configuration write would be refused. Does not save.
   */
  private function probeConfigChange(?McpPolicyProfileInterface $profile): McpInstallCheck {
    $title = 'A configuration change is refused';
    if ($profile === NULL) {
      return McpInstallCheck::skipped('probe_config_change', $title, 'no policy profile is available to evaluate a config write.');
    }
    if ($profile->allowsConfigWrite()) {
      return McpInstallCheck::notApplicable(
        'probe_config_change',
        $title,
        sprintf('profile %s grants config write; a served write is in tier here.', $profile->id()),
      );
    }
    $access = $this->accessChecker->checkConfigAccess('system.site', 'write', $profile);
    if ($access->isForbidden()) {
      $reason = $access instanceof AccessResultReasonInterface
        ? (string) $access->getReason()
        : '';
      return McpInstallCheck::pass('probe_config_change', $title, [], [], [
        'reason' => $reason,
      ]);
    }
    return McpInstallCheck::fail('probe_config_change', $title, [
      'a configuration write to system.site would be allowed.',
    ]);
  }

  /**
   * An edit of live content would be refused or redirected. Does not save.
   */
  private function probeLiveContentEdit(
    ?McpPolicyProfileInterface $profile,
    ?string $contentTarget,
  ): McpInstallCheck {
    $title = 'An edit to live content is refused or redirected';
    if ($contentTarget === NULL || $contentTarget === '') {
      return McpInstallCheck::skipped(
        'probe_live_content_edit',
        $title,
        'no content target supplied (--content-target <uuid>), so the live-edit gate was never reached. Point it at a node you would not mind being published if the gate failed; this probe still does not save.',
      );
    }
    if ($profile === NULL) {
      return McpInstallCheck::skipped('probe_live_content_edit', $title, 'no policy profile is available to evaluate a live edit.');
    }
    $nodes = $this->entityTypeManager->getStorage('node')->loadByProperties([
      'uuid' => $contentTarget,
    ]);
    $node = $nodes ? reset($nodes) : NULL;
    if (!$node instanceof Node) {
      return McpInstallCheck::skipped(
        'probe_live_content_edit',
        $title,
        sprintf('no node with uuid %s exists, so the live-edit gate was never reached.', $contentTarget),
      );
    }
    // Re-state the published flag on a clone so validate() sees a
    // publish-bearing edit. The stored entity is never saved or mutated.
    $probe = clone $node;
    $probe->setPublished();
    $observed = $this->asGovernedAgent(function () use ($probe): array {
      return [
        'decision' => $this->unmoderatedRedirect->classify($probe),
        'violations' => $probe->validate(),
      ];
    });
    if ($observed === NULL) {
      return McpInstallCheck::skipped(
        'probe_live_content_edit',
        $title,
        'no governed account exists, so the live-edit gate would not engage.',
      );
    }
    $decision = $observed['decision'];
    $violations = $observed['violations'];
    $denied = $this->hasDenyPublishViolation($violations);
    $redirected = $decision === McpUnmoderatedForwardRevision::DECISION_REDIRECT
      || $decision === McpUnmoderatedForwardRevision::DECISION_DENY;
    if ($denied || $redirected) {
      return McpInstallCheck::pass('probe_live_content_edit', $title, [], [], [
        'target' => $contentTarget,
        'decision' => $decision,
        'denied' => $denied,
      ]);
    }
    return McpInstallCheck::fail('probe_live_content_edit', $title, [
      'a publish-bearing edit would neither be refused nor redirected; the live default is unprotected.',
    ], [], [
      'target' => $contentTarget,
      'decision' => $decision,
    ]);
  }

  /**
   * Profile of the same account the write probes validate as.
   *
   * Uses that account's roles, not the union of every governed role, so
   * access and validate() cannot disagree on which policy applies.
   */
  private function productionProfile(): ?McpPolicyProfileInterface {
    $account = $this->firstGovernedAccount();
    $roles = $account !== NULL
      ? $account->getRoles()
      : $this->policyResolver->getGovernedRoles();
    return $this->policyResolver->resolveForRoles($roles);
  }

  /**
   * Enabled policy profiles.
   *
   * @return \Drupal\mcp_sentinel\McpPolicyProfileInterface[]
   *   Profiles.
   */
  private function enabledProfiles(): array {
    $profiles = $this->entityTypeManager->getStorage('mcp_policy_profile')->loadMultiple();
    $enabled = [];
    foreach ($profiles as $profile) {
      if ($profile instanceof McpPolicyProfileInterface && $profile->status()) {
        $enabled[] = $profile;
      }
    }
    return $enabled;
  }

  /**
   * First existing node type, or the requested one when it exists.
   */
  private function resolveBundle(?string $requested): ?string {
    $storage = $this->entityTypeManager->getStorage('node_type');
    if ($requested !== NULL && $requested !== '') {
      return $storage->load($requested) !== NULL ? $requested : NULL;
    }
    $types = $storage->loadMultiple();
    $type = reset($types);
    return $type ? $type->id() : NULL;
  }

  /**
   * An unsaved node used only for access and validation.
   */
  private function unsavedNode(string $bundle, bool $published): Node {
    $node = Node::create([
      'type' => $bundle,
      'title' => 'MCP Sentinel verification (not saved)',
      'status' => $published ? 1 : 0,
      'uid' => $this->currentUser->id() ?: 0,
    ]);
    if ($published) {
      $node->setPublished();
    }
    else {
      $node->setUnpublished();
    }
    return $node;
  }

  /**
   * Puts the unsaved node into a go-live shape the deny-publish gate sees.
   *
   * Unmoderated types publish via status. Moderated types publish via
   * moderation_state; status alone stays at the workflow default (usually
   * draft) and the constraint never fires.
   *
   * @return bool
   *   TRUE when a go-live could be represented on this entity.
   */
  private function applyGoLive(Node $node): bool {
    $node->setPublished();
    if ($this->moderationInformation === NULL
      || !$this->moderationInformation->isModeratedEntity($node)) {
      return TRUE;
    }
    $workflow = $this->moderationInformation->getWorkflowForEntity($node);
    if ($workflow === NULL) {
      return FALSE;
    }
    foreach ($workflow->getTypePlugin()->getStates() as $state) {
      if ($state instanceof ContentModerationState && $state->isPublishedState()) {
        $node->set('moderation_state', $state->id());
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Runs a callback as a governed agent on the verification channel.
   *
   * Switches the current user to a non-anonymous account that holds a
   * governed role (so resolve() selects the role-bound profile) and
   * sets the process-scoped agent-channel flag (so isGoverned() is
   * TRUE without minting a token). Always restores both.
   *
   * @param callable(): mixed $callback
   *   Work that must see the publish/write gates.
   *
   * @return mixed
   *   The callback return value, or NULL when no governed account exists.
   */
  private function asGovernedAgent(callable $callback): mixed {
    $account = $this->firstGovernedAccount();
    if ($account === NULL) {
      return NULL;
    }
    $previous = $this->currentUser->getAccount();
    $this->currentUser->setAccount($account);
    $this->oauthContext->setVerificationChannel(TRUE);
    try {
      return $callback();
    }
    finally {
      $this->oauthContext->setVerificationChannel(FALSE);
      $this->currentUser->setAccount($previous);
    }
  }

  /**
   * First active user that holds a governed role.
   */
  private function firstGovernedAccount(): ?AccountInterface {
    $roles = $this->policyResolver->getGovernedRoles();
    if ($roles === []) {
      return NULL;
    }
    $ids = $this->entityTypeManager->getStorage('user')->getQuery()
      ->accessCheck(FALSE)
      ->condition('roles', $roles, 'IN')
      ->condition('status', 1)
      ->range(0, 1)
      ->execute();
    if ($ids === []) {
      return NULL;
    }
    $account = $this->entityTypeManager->getStorage('user')->load(reset($ids));
    return $account instanceof AccountInterface ? $account : NULL;
  }

  /**
   * Whether a violation list contains the deny-publish message.
   */
  private function hasDenyPublishViolation(ConstraintViolationListInterface $violations): bool {
    $needle = (new McpDenyPublish())->message;
    foreach ($violations as $violation) {
      $template = (string) $violation->getMessageTemplate();
      $message = (string) $violation->getMessage();
      if (str_contains($template, $needle) || str_contains($message, $needle)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Stable digest of verified configuration, secrets excluded.
   */
  private function configDigest(): string {
    $settings = $this->configFactory->get('mcp_sentinel.settings')->get() ?? [];
    $profiles = [];
    foreach ($this->enabledProfiles() as $profile) {
      $profiles[$profile->id()] = [
        'roles' => $profile->getRoles(),
        'allow_read' => $profile->allowsRead(),
        'allow_write' => $profile->allowsWrite(),
        'allow_delete' => $profile->allowsDelete(),
        'allow_config_write' => $profile->allowsConfigWrite(),
        'deny_publish' => $profile->deniesPublish(),
      ];
    }
    $payload = [
      'settings' => self::redact($settings),
      'profiles' => $profiles,
    ];
    return 'sha256:' . hash(
      'sha256',
      (string) json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
    );
  }

  /**
   * Findings for W&L identifiers, non-neutral hosts, and shipped secrets.
   *
   * @param string $rel
   *   File basename.
   * @param string $text
   *   File contents.
   *
   * @return string[]
   *   Findings.
   */
  private static function findingsInText(string $rel, string $text): array {
    $findings = [];
    foreach (preg_split("/\r\n|\n|\r/", $text) ?: [] as $index => $line) {
      if (self::isWilkesLibertyIdentifier($line)
        && !self::isPublicProjectReference($line)) {
        $findings[] = sprintf(
          '%s:%d names a W&L identifier.',
          $rel,
          $index + 1,
        );
      }
    }
    foreach (self::hostsInText($text) as $host) {
      if (!self::isNeutralHost($host)) {
        $findings[] = sprintf('%s names host %s.', $rel, $host);
      }
    }
    if (preg_match('/^webhook_secret:\s*(.+?)\s*$/m', $text, $match) === 1) {
      $value = trim($match[1], '\'"');
      if ($value !== '' && $value !== 'null' && $value !== '~') {
        $findings[] = sprintf('%s ships a webhook_secret value.', $rel);
      }
    }
    return $findings;
  }

  /**
   * Hostnames mentioned as URLs or bare host-shaped strings.
   *
   * @param string $text
   *   File contents.
   *
   * @return string[]
   *   Hosts, lowercased, unique.
   */
  private static function hostsInText(string $text): array {
    $hosts = [];
    if (preg_match_all('#https?://([^/\s\'"]+)#i', $text, $matches) !== FALSE) {
      foreach ($matches[1] as $raw) {
        $host = strtolower(explode(':', $raw)[0]);
        if ($host !== '') {
          $hosts[$host] = $host;
        }
      }
    }
    return array_values($hosts);
  }

  /**
   * Whether a string names the W&L estate.
   */
  private static function isWilkesLibertyIdentifier(string $value): bool {
    return preg_match('/wilkesliberty|wilkes-liberty/i', $value) === 1;
  }

  /**
   * Whether a W&L mention is the public GitHub org, not a tenant host.
   */
  private static function isPublicProjectReference(string $value): bool {
    return preg_match('/github\.com\/Wilkes-Liberty/i', $value) === 1;
  }

  /**
   * Every string value in a nested structure, with its path.
   *
   * @param mixed $value
   *   Any JSON-ish value.
   * @param string[] $path
   *   Accumulated key path.
   *
   * @return array<int, array{path: string, value: string}>
   *   Leaves.
   */
  private static function strings(mixed $value, array $path = []): array {
    if (is_string($value)) {
      return [['path' => implode('.', $path), 'value' => $value]];
    }
    if (is_array($value)) {
      $out = [];
      foreach ($value as $key => $item) {
        $out = array_merge($out, self::strings($item, [...$path, (string) $key]));
      }
      return $out;
    }
    return [];
  }

  /**
   * Drops secret-shaped keys from a nested array.
   *
   * @param mixed $value
   *   Config value.
   *
   * @return mixed
   *   Redacted copy.
   */
  private static function redact(mixed $value): mixed {
    if (!is_array($value)) {
      return $value;
    }
    $out = [];
    foreach ($value as $key => $item) {
      $name = strtolower((string) $key);
      if (str_contains($name, 'secret')
        || str_contains($name, 'password')
        || str_contains($name, 'token')) {
        $out[$key] = $item === '' || $item === NULL || $item === [] ? $item : '[redacted]';
        continue;
      }
      $out[$key] = self::redact($item);
    }
    return $out;
  }

}
