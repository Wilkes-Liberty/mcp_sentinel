<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\Core\Entity\FieldableEntityInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\tool\ExecutableResult;

/**
 * Shared helpers for MCP Sentinel content tool plugins.
 */
trait McpEntityToolTrait {

  /**
   * Returns the denial reason for a forbidden access result, or NULL.
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
   * Validates an entity and returns human-readable violation messages.
   *
   * @return string[]
   *   Violation messages (empty when the entity is valid).
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
      $results['_result_cap'] = $profile->getResultCountCap();
    }
    return $results;
  }

  /**
   * Checks if a serialized payload exceeds the profile's response_size_cap.
   *
   * Returns a failure result when over-cap, NULL when within limits.
   *
   * @param string $serialized
   *   The serialized response string whose byte length will be measured.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The active governance profile.
   *
   * @return \Drupal\tool\ExecutableResult|null
   *   A failure result when over the cap, NULL when within limits.
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
            '@cap'   => $profile->getResponseSizeCap(),
          ]
        )
      );
    }
    return NULL;
  }

}
