<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\EntityInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Selects audit minimization at a trusted application boundary.
 *
 * Implementations may use verified server context or an actual resolved
 * resource. Request arguments, headers and metadata are not policy selectors.
 */
interface McpAuditEvidencePolicyInterface {

  /**
   * Returns a projection for this evidence, or NULL for standard audit.
   */
  public function projection(?Request $request, ?EntityInterface $resource): ?McpAuditEvidenceProjectionInterface;

}
