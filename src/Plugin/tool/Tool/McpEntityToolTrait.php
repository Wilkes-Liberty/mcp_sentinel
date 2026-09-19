<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\Core\Entity\FieldableEntityInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\tool\ExecutableResult;

/**
 * Shared helpers for governed tool plugins, in this project and in others.
 *
 * Every protected method here is API for downstream tool authors. Modules
 * outside this project use this trait on a McpGovernedToolBase subclass and
 * call these helpers. MCP Sentinel's own tools do not call all of them, so a
 * search of this project alone reports some as unused. They are not dead
 * code: 2.22.1 removed checkResponseSizeCap() on that reading and every
 * GraphQL Compose Codegen MCP tool began refusing every request.
 *
 * Removing, renaming or changing the signature of a method tagged "@api" is a
 * breaking change and needs a major release. The mcp_sentinel_downstream_test
 * module calls each helper from another namespace and
 * McpDownstreamToolContractTest compares this trait with a pinned list, so
 * either change fails this project's own tests.
 *
 * @see \Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\DownstreamContractTool
 * @see \Drupal\Tests\mcp_sentinel\Kernel\McpDownstreamToolContractTest
 */
trait McpEntityToolTrait {

  /**
   * Returns the denial reason for a forbidden access result, or NULL.
   *
   * @api
   */
  protected function denyReason(AccessResultInterface $result): ?string {
    if (!$result->isForbidden()) {
      return NULL;
    }
    return $result instanceof AccessResultReasonInterface && $result->getReason()
      ? (string) $result->getReason()
      : 'denied by policy';
  }

  /**
   * Writes a denied_access audit row for a governed-tool policy denial.
   *
   * Only called from explicit Tool execution paths (not from entity access
   * hooks) so volume is bounded to the requests an agent explicitly sends.
   * The audit_log_reads toggle is intentionally ignored; denied_access is a
   * security event that must always be recorded when audit_enabled is true.
   *
   * JSON:API / GraphQL denial logging is a future enhancement (F10 v2).
   *
   * @param string $toolId
   *   The plugin ID of the tool handling the denial.
   * @param string $entityType
   *   The entity type being operated on.
   * @param string $entityId
   *   The entity ID, or '(new)' for create operations.
   * @param string $operation
   *   The attempted operation (e.g. 'create', 'update', 'delete').
   * @param string $reason
   *   Human-readable denial reason (from denyReason() or inline text).
   *
   * @api
   */
  protected function logDeniedAccess(
    string $toolId,
    string $entityType,
    string $entityId,
    string $operation,
    string $reason,
  ): void {
    \Drupal::service('mcp_sentinel.audit_logger')->log('denied_access', [
      'tool'        => $toolId,
      'entity_type' => $entityType,
      'id'          => $entityId,
      'operation'   => $operation,
      'reason'      => $reason,
    ]);
  }

  /**
   * Validates an entity and returns human-readable violation messages.
   *
   * @return string[]
   *   Violation messages (empty when the entity is valid).
   *
   * @api
   */
  protected function validationMessages(FieldableEntityInterface $entity): array {
    $messages = [];
    foreach ($entity->validate() as $violation) {
      $messages[] = $violation->getPropertyPath() . ': ' . strip_tags((string) $violation->getMessage());
    }
    return $messages;
  }

  /**
   * Checks the rate limit; returns a failure result on breach, NULL otherwise.
   *
   * Registers a hit on success. Call this after resolving $profile and before
   * any business logic. The audit log entry ensures over-limit traffic is
   * visible in reports.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   * @param string $toolId
   *   The tool plugin ID used as part of the flood key.
   *
   * @return \Drupal\tool\ExecutableResult|null
   *   A failure result when throttled, NULL when within limits.
   *
   * @api
   */
  protected function checkRateLimit(
    McpPolicyProfileInterface $profile,
    string $toolId,
  ): ?ExecutableResult {
    /** @var \Drupal\mcp_sentinel\Service\McpRateLimiter $limiter */
    $limiter = \Drupal::service('mcp_sentinel.rate_limiter');
    $uid = (int) $this->currentUser->id();
    if (!$limiter->check($profile, $uid, $toolId)) {
      \Drupal::service('mcp_sentinel.audit_logger')->log(
        'rate_limit_exceeded', ['tool' => $toolId],
      );
      return ExecutableResult::failure(
        $this->t('Rate limit exceeded. Retry after the current window expires.')
      );
    }
    $limiter->register($profile, $uid, $toolId);
    return NULL;
  }

  /**
   * Applies the profile's result_count_cap to a bulk-results array.
   *
   * Only 'succeeded' is truncated — 'failed' and 'queued' are always fully
   * returned so the caller can retry failed items correctly. When truncation
   * occurs, '_result_truncated' (TRUE) and '_result_cap' (int) are added to
   * the results array so the agent is never silently misled.
   *
   * @param array $results
   *   The results array with 'succeeded', 'failed', and 'queued' keys.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The active governance profile supplying the cap.
   *
   * @return array
   *   The (possibly truncated) results array.
   *
   * @api
   */
  protected function applyResultCap(
    array $results,
    McpPolicyProfileInterface $profile,
  ): array {
    /** @var \Drupal\mcp_sentinel\Service\McpExfiltrationGuard $guard */
    $guard = \Drupal::service('mcp_sentinel.exfiltration_guard');
    [$capped, $truncated] = $guard->capResults($results['succeeded'] ?? [], $profile);
    $results['succeeded'] = $capped;
    if ($truncated) {
      $results['_result_truncated'] = TRUE;
      $results['_result_cap'] = $guard->effectiveResultCap($profile);
    }
    return $results;
  }

  /**
   * Checks if a serialized payload exceeds the profile's response_size_cap.
   *
   * Returns a failure result when over-cap, NULL when within limits.
   *
   * This is appropriate for PURE-READ tools that want to refuse-with-failure
   * before materialising any response. For write tools (where operations have
   * already been executed), use truncateBulkResultsToSizeCap() instead so that
   * completed work is never misreported as failed.
   *
   * @param string $serialized
   *   The serialized response string whose byte length will be measured.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The active governance profile.
   *
   * @return \Drupal\tool\ExecutableResult|null
   *   A failure result when over the cap, NULL when within limits.
   *
   * @api
   */
  protected function checkResponseSizeCap(
    string $serialized,
    McpPolicyProfileInterface $profile,
  ): ?ExecutableResult {
    /** @var \Drupal\mcp_sentinel\Service\McpExfiltrationGuard $guard */
    $guard = \Drupal::service('mcp_sentinel.exfiltration_guard');
    $bytes = strlen($serialized);
    if ($guard->exceedsResponseSizeCap($bytes, $profile)) {
      return ExecutableResult::failure(
        $this->t(
          'Response size @bytes bytes exceeds the MCP Sentinel cap of @cap bytes for this profile. Narrow your query.',
          [
            '@bytes' => $bytes,
            '@cap'   => $guard->effectiveResponseSizeCap($profile),
          ]
        )
      );
    }
    return NULL;
  }

  /**
   * Truncates a completed bulk-write results array to honour the size cap.
   *
   * This method is intended for bulk WRITE tools only. Because the operations
   * have already been executed, returning ExecutableResult::failure() would
   * misreport a completed write batch — an agent seeing "failure" may retry,
   * toggling publish/unpublish state or re-deleting entities.
   *
   * Instead, when the serialised payload exceeds the cap, the 'succeeded' (and
   * if needed 'failed') lists are truncated enough to fit under the limit, and
   * '_size_truncated: true' plus '_size_cap' are added to the results array.
   * The method always returns the (possibly truncated) results array unchanged
   * when the cap is 0 (unlimited) or is not exceeded.
   *
   * @param array $results
   *   The results array with 'succeeded', 'failed', and 'queued' keys.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The active governance profile supplying the cap.
   *
   * @return array
   *   The (possibly truncated) results array with '_size_truncated' and
   *   '_size_cap' keys added when truncation was necessary.
   *
   * @api
   */
  protected function truncateBulkResultsToSizeCap(
    array $results,
    McpPolicyProfileInterface $profile,
  ): array {
    /** @var \Drupal\mcp_sentinel\Service\McpExfiltrationGuard $guard */
    $guard = \Drupal::service('mcp_sentinel.exfiltration_guard');
    $cap = $guard->effectiveResponseSizeCap($profile);
    if ($cap <= 0) {
      return $results;
    }

    $serialized = json_encode($results) ?: '';
    if (strlen($serialized) <= $cap) {
      return $results;
    }

    // Truncate 'succeeded' first — that list is the largest and already
    // subject to result_count_cap truncation. We remove items one-by-one from
    // the tail until the payload fits, rather than guessing a proportion.
    while (!empty($results['succeeded']) && strlen(json_encode($results) ?: '') > $cap) {
      array_pop($results['succeeded']);
    }

    // If 'succeeded' is now empty and the payload still exceeds the cap
    // (unlikely but theoretically possible when 'failed' is very large),
    // truncate 'failed' as well.
    while (!empty($results['failed']) && strlen(json_encode($results) ?: '') > $cap) {
      array_pop($results['failed']);
    }

    $results['_size_truncated'] = TRUE;
    $results['_size_cap'] = $cap;
    return $results;
  }

}
