<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Enforces result-count and response-size caps on governed agent responses.
 *
 * Caps are applied BEFORE serialization so the database never exposes excess
 * rows to an agent. A cap of 0 (the default) is treated as unlimited and the
 * guard short-circuits without examining the data.
 */
final class McpExfiltrationGuard {

  /**
   * Truncates $data to the profile's result_count_cap when the cap is active.
   *
   * @param array $data
   *   The result list to check. Keys are preserved on the returned slice.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The active governance profile.
   *
   * @return array{0: array, 1: bool}
   *   A two-element tuple: [capped_data, was_truncated]. When the cap is 0
   *   (unlimited) or the list is at/under the cap, $data is returned unchanged
   *   and was_truncated is FALSE.
   */
  public function capResults(array $data, McpPolicyProfileInterface $profile): array {
    $cap = $profile->getResultCountCap();
    if ($cap > 0 && count($data) > $cap) {
      return [array_slice($data, 0, $cap), TRUE];
    }
    return [$data, FALSE];
  }

  /**
   * Returns TRUE when $bytes exceeds the profile's response_size_cap.
   *
   * A cap of 0 is unlimited and always returns FALSE.
   *
   * @param int $bytes
   *   The byte length of the serialized response.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The active governance profile.
   *
   * @return bool
   *   TRUE when an active size cap is set and $bytes exceeds it; FALSE when the
   *   cap is unlimited (0) or the response is within the cap.
   */
  public function exceedsResponseSizeCap(int $bytes, McpPolicyProfileInterface $profile): bool {
    $cap = $profile->getResponseSizeCap();
    return $cap > 0 && $bytes > $cap;
  }

}
