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

        $create = clone $route;
        $create->setPath($route->getPath() . '/mcp-draft/translations');
        $create->setMethods(['POST']);
        $create->setDefault('_controller', 'jsonapi.entity_resource.mcp_draft:postTranslation');
        $collection->add($name . '.mcp_draft_translations', $create);
      }
      // GET individual is jsonapi.node--{bundle}.individual (no ".get" suffix).
      if (str_starts_with($name, 'jsonapi.node--')
        && str_ends_with($name, '.individual')) {
        $inventory = clone $route;
        $inventory->setPath($route->getPath() . '/mcp-translations');
        $inventory->setMethods(['GET']);
        $inventory->setDefault('_controller', 'jsonapi.entity_resource.mcp_draft:getTranslationInventory');
        $collection->add($name . '.mcp_translations', $inventory);

        $draft_get = clone $route;
        $draft_get->setPath($route->getPath() . '/mcp-draft');
        $draft_get->setMethods(['GET']);
        $draft_get->setDefault('_controller', 'jsonapi.entity_resource.mcp_draft:getDraftTranslation');
        $collection->add($name . '.mcp_draft_get', $draft_get);
      }
    }
  }

}
