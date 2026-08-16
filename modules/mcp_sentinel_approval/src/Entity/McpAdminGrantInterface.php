<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Entity;

use Drupal\Core\Entity\ContentEntityInterface;

/**
 * Defines the interface for a time-boxed mcp_admin break-glass grant.
 */
interface McpAdminGrantInterface extends ContentEntityInterface {

  /**
   * Gets the grantee user id.
   */
  public function getUserId(): int;

  /**
   * Gets the expiry timestamp.
   */
  public function getExpires(): int;

  /**
   * Whether the grant has been revoked.
   */
  public function isRevoked(): bool;

  /**
   * Sets the revoked flag.
   *
   * @param bool $revoked
   *   TRUE to mark revoked.
   *
   * @return $this
   */
  public function setRevoked(bool $revoked = TRUE): static;

  /**
   * The HMAC-sealed grant manifest, or empty when none was stored.
   */
  public function getSealedManifest(): string;

  /**
   * Stores the HMAC-sealed grant manifest.
   *
   * @param string $manifest
   *   Sealed JSON.
   *
   * @return $this
   */
  public function setSealedManifest(string $manifest): static;

}
