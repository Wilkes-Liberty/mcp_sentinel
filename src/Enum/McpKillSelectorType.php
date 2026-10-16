<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Kill-registry selector kinds (DEV-846).
 *
 * Principal_key is one agent (iss|sub|actor). human_key is every
 * agent of this person (iss|sub). tenant is tenant-wide.
 */
enum McpKillSelectorType: string {

  case PrincipalKey = 'principal_key';
  case HumanKey = 'human_key';
  case Tenant = 'tenant';

  /**
   * Whether this selector is a mass kill by itself.
   *
   * A human_key or tenant selector always needs two operators. A
   * single principal_key does not; more than one principal_key in
   * one request does.
   */
  public function isMassByItself(): bool {
    return match ($this) {
      self::PrincipalKey => FALSE,
      self::HumanKey, self::Tenant => TRUE,
    };
  }

}
