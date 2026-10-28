<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Exception;

/**
 * Refuses to compose a principal key (fail closed, no key).
 *
 * Reason codes match tests/fixtures/principal-key-vectors.json so a
 * JS twin can assert the same errors.
 */
final class McpPrincipalKeyException extends \RuntimeException {

  /**
   * Token omitted iss.
   */
  public const MISSING_ISS = 'missing_iss';

  /**
   * Token omitted sub.
   */
  public const MISSING_SUB = 'missing_sub';

  /**
   * No act claim and no azp.
   */
  public const MISSING_AZP = 'missing_azp';

  /**
   * An act claim is present but top-level act.sub is missing.
   */
  public const MISSING_ACT_SUB = 'missing_act_sub';

  /**
   * The act.sub claim equals azp, or azp already uses the act prefix.
   */
  public const ACTOR_CLAIM_COLLISION = 'actor_claim_collision';

  /**
   * A '|' in iss, sub, or actor would make the key forgeable.
   */
  public const INVALID_SEPARATOR = 'invalid_separator';

  /**
   * A part is whitespace-only or contains a control character.
   */
  public const INVALID_PART = 'invalid_part';

  /**
   * A part exceeds MAX_PART_LENGTH (256) characters.
   */
  public const PART_TOO_LONG = 'part_too_long';

  /**
   * A part is not valid UTF-8.
   */
  public const INVALID_UTF8 = 'invalid_utf8';

  /**
   * Constructs a fail-closed key refusal.
   *
   * @param string $reasonCode
   *   Stable machine reason (shared with the vector file).
   * @param string $message
   *   Operator-facing text. Must not contain secrets.
   */
  public function __construct(
    public readonly string $reasonCode,
    string $message,
  ) {
    parent::__construct($message);
  }

}
