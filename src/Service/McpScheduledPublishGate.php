<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\Access\AccessResult;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableStorageInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Decides scheduled publishing for governed requests (d.o #3627557).
 *
 * Scheduler Content Moderation Integration (SCMI) adds publish_state and
 * unpublish_state to moderated entity types and authorizes a scheduled state
 * with the account's workflow transition permissions, in three places:
 *
 * 1. The SchedulerModerationTransitionAccess constraint on both fields.
 * 2. The fields' allowed-values function, built from the current user's valid
 *    transitions.
 * 3. scheduler_content_moderation_integration_entity_access(), which forbids
 *    update when a stored scheduled state is one the account cannot use.
 *
 * MCP Sentinel replaces all three with wrappers that call SCMI's originals for
 * every request this service does not take over, so human traffic keeps SCMI's
 * behaviour exactly. For a governed request the policy profile decides:
 *
 * - allow_scheduled_publish off: a write that sets or changes a scheduled
 *   state is refused. Wrappers 1-3 still delegate to SCMI.
 * - allow_scheduled_publish on: the scheduled state must be a transition the
 *   entity's workflow defines from the state it is scheduled from, at or below
 *   max_moderation_state. The role's transition permissions are not consulted.
 *
 * Immediate publishing is not decided here; the McpDenyPublish constraint and
 * the role's permissions govern it as before.
 */
final class McpScheduledPublishGate {

  /**
   * The SCMI module machine name.
   */
  public const SCMI_MODULE = 'scheduler_content_moderation_integration';

  /**
   * SCMI's allowed-values function for publish_state and unpublish_state.
   */
  public const SCMI_ALLOWED_VALUES = '_scheduler_content_moderation_integration_states_values';

  /**
   * SCMI's hook_entity_access() implementation.
   */
  public const SCMI_ACCESS_HOOK = 'scheduler_content_moderation_integration_entity_access';

  /**
   * SCMI's transition-permission constraint plugin ID.
   */
  public const SCMI_TRANSITION_CONSTRAINT = 'SchedulerModerationTransitionAccess';

  /**
   * Scheduled-state fields, keyed by the date field that activates them.
   */
  public const FIELDS = [
    'publish_state' => 'publish_on',
    'unpublish_state' => 'unpublish_on',
  ];

  /**
   * Refusal when the profile does not allow scheduled publishing.
   *
   * Kept verbatim: tests and callers match on this string.
   */
  public const DENY_MESSAGE = 'Scheduled publishing is denied by MCP Sentinel for this profile.';

  /**
   * Refusal when a scheduled publish is not in the future under deny_publish.
   */
  public const NOT_FUTURE_MESSAGE = 'Scheduling is denied by MCP Sentinel: a scheduled publish or unpublish date must be in the future.';

  /**
   * Constructs the gate.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves whether the request is governed and which profile applies.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Loads the stored entity to compare the incoming schedule against.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   Tells whether SCMI is installed.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Records allowed scheduled transitions and refused unvalidated saves.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The request time, to tell a schedule from an immediate publish.
   * @param \Drupal\content_moderation\ModerationInformationInterface|null $moderationInformation
   *   The moderation information service, or NULL when Content Moderation is
   *   not installed.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly McpAuditLogger $auditLogger,
    private readonly TimeInterface $time,
    private readonly ?ModerationInformationInterface $moderationInformation = NULL,
  ) {}

  /**
   * Whether SCMI is installed, so there is anything to gate.
   */
  public function isActive(): bool {
    return $this->moderationInformation !== NULL
      && $this->moduleHandler->moduleExists(self::SCMI_MODULE);
  }

  /**
   * Whether Sentinel replaces SCMI's permission checks for this request.
   *
   * TRUE only for a governed account whose profile allows scheduled
   * publishing for the entity type. Every other request is handed to SCMI.
   *
   * @param string $entity_type_id
   *   The entity type being scheduled.
   * @param \Drupal\Core\Session\AccountInterface|null $account
   *   The account, or NULL for the current user.
   */
  public function takesOver(string $entity_type_id, ?AccountInterface $account = NULL): bool {
    $profile = $this->policyResolver->resolve($account);
    return $profile !== NULL && $profile->allowsScheduledPublishForEntityType($entity_type_id);
  }

  /**
   * Whether the entity carries SCMI's scheduled-state fields under moderation.
   */
  public function appliesTo(EntityInterface $entity): bool {
    return $this->isActive()
      && $entity instanceof ContentEntityInterface
      && $entity->hasField('publish_state')
      && $entity->hasField('unpublish_state')
      && $this->moderationInformation->isModeratedEntity($entity);
  }

  /**
   * The schedule pairs a write sets or changes.
   *
   * A scheduled state takes effect only with its date, the same rule SCMI's
   * validators apply. A pair counts as a change when it is scheduled and
   * differs from the stored pair, so an agent editing content a human already
   * scheduled is not refused for the human's schedule.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity carrying the incoming values.
   * @param \Drupal\Core\Entity\ContentEntityInterface|null $original
   *   The stored entity, or NULL for a new one.
   *
   * @return array<string, array{state: string, on: int, from: string}>
   *   Changed scheduled pairs keyed by state field name. 'from' is the state
   *   the scheduled transition starts from.
   */
  public function scheduledChanges(ContentEntityInterface $entity, ?ContentEntityInterface $original): array {
    $changes = [];
    foreach ($this->scheduledPairs($entity) as $field => $pair) {
      $before = $original !== NULL ? ($this->scheduledPairs($original)[$field] ?? NULL) : NULL;
      if ($before !== NULL && $before['state'] === $pair['state'] && $before['on'] === $pair['on']) {
        continue;
      }
      $changes[$field] = $pair;
    }
    return $changes;
  }

  /**
   * The stored version of the entity being validated.
   *
   * Validation runs before the save, when the original is not populated, so
   * the stored entity is loaded, in the same translation.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being validated.
   *
   * @return \Drupal\Core\Entity\ContentEntityInterface|null
   *   The stored entity, or NULL when the entity is new.
   */
  public function storedOriginal(ContentEntityInterface $entity): ?ContentEntityInterface {
    if ($entity->isNew()) {
      return NULL;
    }
    // Compare with the revision the write was loaded from, as core's presave
    // does, so a forward draft is compared with itself and not with the
    // default revision.
    $storage = $this->entityTypeManager->getStorage($entity->getEntityTypeId());
    $revision_id = $entity->getLoadedRevisionId();
    if (!empty($revision_id) && $storage instanceof RevisionableStorageInterface) {
      // Drupal 10.6 has no loadRevisionUnchanged(); the else branch is its
      // fallback.
      // @phpstan-ignore function.alreadyNarrowedType
      if (method_exists($storage, 'loadRevisionUnchanged')) {
        $stored = $storage->loadRevisionUnchanged($revision_id);
      }
      else {
        $storage->resetCache([$entity->id()]);
        $stored = $storage->loadRevision($revision_id);
      }
    }
    else {
      $stored = $storage->loadUnchanged($entity->id());
    }
    if (!$stored instanceof ContentEntityInterface) {
      return NULL;
    }
    $langcode = $entity->language()->getId();
    return $stored->hasTranslation($langcode) ? $stored->getTranslation($langcode) : NULL;
  }

  /**
   * Why a governed write's scheduled changes are refused.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity carrying the incoming values.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved profile.
   * @param array<string, array{state: string, on: int, from: string}> $changes
   *   The changes from ::scheduledChanges().
   *
   * @return string[]
   *   Refusal messages; empty when every change is allowed.
   */
  public function refusals(ContentEntityInterface $entity, McpPolicyProfileInterface $profile, array $changes): array {
    if ($changes === []) {
      return [];
    }
    if (!$profile->allowsScheduledPublishForEntityType($entity->getEntityTypeId())) {
      return [self::DENY_MESSAGE];
    }
    $messages = [];
    foreach ($changes as $pair) {
      // Scheduler acts on a past date in the same save, which would be an
      // immediate transition the role may not hold. Only future dates are
      // schedules.
      if ($pair['on'] <= $this->time->getRequestTime()) {
        $messages[] = self::NOT_FUTURE_MESSAGE;
        continue;
      }
      $reason = $this->stateRefusal($entity, $profile, $pair['from'], $pair['state']);
      if ($reason !== NULL) {
        $messages[] = $reason;
      }
    }
    return $messages;
  }

  /**
   * Refuses a governed save that never validated.
   *
   * The constraint reports refusals on the validated seams (JSON:API, REST,
   * forms, the Sentinel tools). This is the unvalidated seam: custom code and
   * Drush. The save is aborted after an audit row that survives the rollback.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being saved.
   *
   * @throws \RuntimeException
   *   When the save sets a scheduled state the profile does not allow.
   */
  public function enforceOnSave(EntityInterface $entity): void {
    if (!$entity instanceof ContentEntityInterface || !$this->appliesTo($entity)) {
      return;
    }
    $profile = $this->policyResolver->resolve();
    if ($profile === NULL) {
      return;
    }
    $changes = $this->scheduledChanges($entity, $this->originalTranslation($entity));
    $refusals = $this->refusals($entity, $profile, $changes);
    if ($refusals === []) {
      return;
    }
    $this->auditLogger->logSurvivingRollback('scheduled_publish_refused', [
      'entity_type' => $entity->getEntityTypeId(),
      'bundle' => $entity->bundle(),
      'id' => $entity->id() ?: '(new)',
      'label' => $entity->label(),
      'scheduled' => $this->describe($changes),
      'note' => 'Governed save refused by the scheduled-publish gate (unvalidated seam); the save was aborted.',
    ]);
    throw new \RuntimeException(implode(' ', $refusals));
  }

  /**
   * Records each scheduled transition a governed save set.
   *
   * Runs after the save. Only governed saves reach the audit log, and an
   * unchanged schedule is not recorded again.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The just-saved entity.
   */
  public function auditSaved(EntityInterface $entity): void {
    if (!$entity instanceof ContentEntityInterface || !$this->appliesTo($entity)) {
      return;
    }
    $profile = $this->policyResolver->resolve();
    if ($profile === NULL) {
      return;
    }
    $changes = $this->scheduledChanges($entity, $this->originalTranslation($entity));
    foreach ($changes as $field => $pair) {
      $this->auditLogger->log('scheduled_transition', [
        'entity_type' => $entity->getEntityTypeId(),
        'bundle' => $entity->bundle(),
        'id' => $entity->id(),
        'label' => $entity->label(),
        'field' => $field,
        'from_state' => $pair['from'],
        'to_state' => $pair['state'],
        'scheduled_for' => $pair['on'],
        'profile' => $profile->id(),
      ] + $this->auditLogger->translationMetadata($entity));
    }
  }

  /**
   * Whether a governed save may let Scheduler publish an overdue schedule now.
   *
   * Scheduler publishes a past publish_on date during any save. Under
   * deny_publish a governed save must not take content live, so the publish
   * waits for cron, which runs ungoverned.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being saved.
   *
   * @return bool
   *   FALSE when this governed save must not publish now.
   */
  public function allowsPublishInSave(EntityInterface $entity): bool {
    if (!$entity instanceof ContentEntityInterface || !$this->appliesTo($entity)) {
      return TRUE;
    }
    $profile = $this->policyResolver->resolve();
    return $profile === NULL || !$profile->deniesPublishForEntityType($entity->getEntityTypeId());
  }

  /**
   * The saved entity's original in the same translation, if it had one.
   *
   * Core sets the original to the stored default translation, so a
   * translation's schedule would be compared with the source language's.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being saved.
   *
   * @return \Drupal\Core\Entity\ContentEntityInterface|null
   *   The original translation, or NULL when the entity or translation is new.
   */
  private function originalTranslation(ContentEntityInterface $entity): ?ContentEntityInterface {
    $original = $this->auditLogger->originalOf($entity);
    if (!$original instanceof ContentEntityInterface) {
      return NULL;
    }
    $langcode = $entity->language()->getId();
    return $original->hasTranslation($langcode) ? $original->getTranslation($langcode) : NULL;
  }

  /**
   * Options for publish_state or unpublish_state on a taken-over request.
   *
   * Mirrors SCMI's allowed-values logic with the workflow's transitions in
   * place of the current user's: a publish option is a published,
   * default-revision state reachable from the current state; an unpublish
   * option is an unpublished, default-revision state reachable from the
   * current state or from one of those publish options. The ceiling is not
   * applied here; the McpScheduledPublish constraint reports it with a
   * message that names it.
   *
   * @param string $field_name
   *   Either 'publish_state' or 'unpublish_state'.
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity the options are for.
   *
   * @return array<string, string>
   *   State labels keyed by state ID, with the '_none' option first.
   */
  public function allowedValues(string $field_name, ContentEntityInterface $entity): array {
    if ($this->moderationInformation === NULL || !$this->moderationInformation->isModeratedEntity($entity)) {
      return [];
    }
    $workflow = $this->moderationInformation->getWorkflowForEntity($entity);
    if ($workflow === NULL) {
      return [];
    }
    $type = $workflow->getTypePlugin();
    $current_id = (string) ($entity->get('moderation_state')->value ?? '');
    if ($current_id === '' || !$type->hasState($current_id)) {
      $current_id = (string) ($type->getConfiguration()['default_moderation_state'] ?? '');
    }
    if (!$type->hasState($current_id)) {
      return [];
    }

    $publish = ['_none' => ''];
    $unpublish = ['_none' => ''];
    $publish_states = [];
    foreach ($type->getState($current_id)->getTransitions() as $transition) {
      $state = $transition->to();
      if (!$state instanceof ContentModerationState || !$state->isDefaultRevisionState()) {
        continue;
      }
      if ($state->isPublishedState()) {
        $publish[$state->id()] = (string) $state->label();
        $publish_states[] = $state;
      }
      else {
        $unpublish[$state->id()] = (string) $state->label();
      }
    }
    foreach ($publish_states as $publish_state) {
      foreach ($publish_state->getTransitions() as $transition) {
        $state = $transition->to();
        if ($state instanceof ContentModerationState && !$state->isPublishedState() && $state->isDefaultRevisionState()) {
          $unpublish[$state->id()] = (string) $state->label();
        }
      }
    }
    return $field_name === 'publish_state' ? $publish : $unpublish;
  }

  /**
   * Replacement for SCMI's hook_entity_access() implementation.
   *
   * Requests the gate does not take over get SCMI's own result. A taken-over
   * request is forbidden update only when a stored scheduled state is one the
   * profile would refuse the agent to set, so the agent is never locked out
   * of content it was allowed to schedule.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being accessed.
   * @param string $operation
   *   The operation.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account.
   */
  public function entityAccess(EntityInterface $entity, string $operation, AccountInterface $account): AccessResultInterface {
    if (!$this->isActive() || !function_exists(self::SCMI_ACCESS_HOOK)) {
      return AccessResult::neutral();
    }
    $profile = $this->policyResolver->resolve($account);
    if ($profile === NULL || !$profile->allowsScheduledPublishForEntityType($entity->getEntityTypeId())) {
      return (self::SCMI_ACCESS_HOOK)($entity, $operation, $account);
    }

    $result = AccessResult::neutral()
      ->addCacheContexts(['user.roles', 'oauth2_scopes'])
      ->addCacheableDependency($profile);
    if ($operation !== 'update' || !$entity instanceof ContentEntityInterface || !$this->appliesTo($entity)) {
      return $result;
    }
    foreach ($this->scheduledPairs($entity) as $pair) {
      if (!$this->transitionExists($entity, $pair['from'], $pair['state'])) {
        // SCMI moves on when the stored state is not a valid transition.
        continue;
      }
      if ($this->stateRefusal($entity, $profile, $pair['from'], $pair['state']) !== NULL) {
        return AccessResult::forbidden('Scheduled transition is not permitted by the MCP Sentinel profile.')
          ->addCacheContexts(['user.roles', 'oauth2_scopes'])
          ->addCacheableDependency($profile)
          ->addCacheableDependency($entity);
      }
    }
    return $result->addCacheableDependency($entity);
  }

  /**
   * Why the profile refuses a scheduled transition, or NULL when it allows it.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The moderated entity.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved profile.
   * @param string $from
   *   The state the scheduled transition starts from.
   * @param string $to
   *   The scheduled state.
   */
  private function stateRefusal(ContentEntityInterface $entity, McpPolicyProfileInterface $profile, string $from, string $to): ?string {
    if (!$this->transitionExists($entity, $from, $to)) {
      return sprintf('Scheduled state "%s" is not a valid transition from "%s" in this workflow.', $to, $from);
    }
    $type = $this->moderationInformation?->getWorkflowForEntity($entity)?->getTypePlugin();
    $max = $profile->getMaxModerationState();
    if ($type !== NULL && $max !== '' && $type->hasState($max)
      && $type->getState($to)->weight() > $type->getState($max)->weight()) {
      return sprintf('Scheduled state "%s" exceeds the maximum permitted state "%s".', $to, $max);
    }
    return NULL;
  }

  /**
   * Whether the entity's workflow defines a transition between the states.
   */
  private function transitionExists(ContentEntityInterface $entity, string $from, string $to): bool {
    $type = $this->moderationInformation?->getWorkflowForEntity($entity)?->getTypePlugin();
    if ($type === NULL || !$type->hasState($from) || !$type->hasState($to)) {
      return FALSE;
    }
    return $type->getState($from)->canTransitionTo($to);
  }

  /**
   * The entity's active schedule pairs.
   *
   * @return array<string, array{state: string, on: int, from: string}>
   *   Scheduled pairs keyed by state field name.
   */
  private function scheduledPairs(ContentEntityInterface $entity): array {
    $pairs = [];
    $current = (string) ($entity->hasField('moderation_state') ? ($entity->get('moderation_state')->value ?? '') : '');
    foreach (self::FIELDS as $field => $date_field) {
      if (!$entity->hasField($field) || !$entity->hasField($date_field)) {
        continue;
      }
      $state = (string) ($entity->get($field)->value ?? '');
      $on = $entity->get($date_field)->value;
      if ($state === '' || $state === '_none' || $on === NULL || $on === '') {
        continue;
      }
      $pairs[$field] = ['state' => $state, 'on' => (int) $on, 'from' => $current];
    }
    // A scheduled unpublish follows a scheduled publish when both are set,
    // the same order SCMI's validators assume.
    if (isset($pairs['unpublish_state'], $pairs['publish_state'])) {
      $pairs['unpublish_state']['from'] = $pairs['publish_state']['state'];
    }
    return $pairs;
  }

  /**
   * Flattens changes for audit metadata.
   *
   * @param array<string, array{state: string, on: int, from: string}> $changes
   *   The changes.
   *
   * @return array<string, string>
   *   "from -> to @ timestamp" keyed by field name.
   */
  private function describe(array $changes): array {
    $out = [];
    foreach ($changes as $field => $pair) {
      $out[$field] = sprintf('%s -> %s @ %d', $pair['from'], $pair['state'], $pair['on']);
    }
    return $out;
  }

}
