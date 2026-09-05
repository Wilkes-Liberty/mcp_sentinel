<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Routing;

use Drupal\Core\Routing\RouteSubscriberBase;
use Symfony\Component\Routing\RouteCollection;

/**
 * Adds node draft routes with the canonical JSON:API access requirements.
 */
final class McpDraftRoutes extends RouteSubscriberBase {

  /**
   * {@inheritdoc}
   */
  protected function alterRoutes(RouteCollection $collection): void {
    foreach ($collection->all() as $name => $route) {
      if (str_starts_with($name, 'jsonapi.node--')
        && str_ends_with($name, '.individual.patch')) {
        $draft = clone $route;
        $draft->setPath($route->getPath() . '/mcp-draft');
        $draft->setDefault('_controller', 'jsonapi.entity_resource.mcp_draft:patchIndividual');
        $collection->add($name . '.mcp_draft', $draft);
      }
    }
  }

}
