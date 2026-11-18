<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\EntityInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Uses standard audit behavior until a site installs an evidence policy.
 */
final class McpDefaultAuditEvidencePolicy implements McpAuditEvidencePolicyInterface {

  /**
   * {@inheritdoc}
   */
  public function projection(?Request $request, ?EntityInterface $resource): ?McpAuditEvidenceProjectionInterface {
    return NULL;
  }

}
