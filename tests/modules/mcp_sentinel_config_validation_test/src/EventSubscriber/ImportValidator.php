<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_config_validation_test\EventSubscriber;

use Drupal\Core\Config\ConfigEvents;
use Drupal\Core\Config\ConfigImporterEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * A module validator of the kind that only runs on config import.
 *
 * The rule cannot be expressed in the schema on purpose: "import_refused" is a
 * valid Choice, so typed-config validation passes and only this subscriber
 * refuses it. The error text repeats the staged value, as real validators do.
 */
final class ImportValidator implements EventSubscriberInterface {

  public const NAME = 'mcp_sentinel_config_validation_test.settings';

  /**
   * The changed names each validation run saw.
   *
   * @var string[][]
   */
  public static array $seen = [];

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [ConfigEvents::IMPORT_VALIDATE => 'onValidate'];
  }

  /**
   * Refuses the one mode this module only checks on import.
   */
  public function onValidate(ConfigImporterEvent $event): void {
    $importer = $event->getConfigImporter();
    $comparer = $importer->getStorageComparer();
    self::$seen[] = array_merge(
      $comparer->getChangelist('create'),
      $comparer->getChangelist('update'),
      $comparer->getChangelist('delete'),
    );
    $staged = $comparer->getSourceStorage()->read(self::NAME);
    if (is_array($staged) && ($staged['mode'] ?? NULL) === 'import_refused') {
      $importer->logError('The mode import_refused is not importable, label was ' . ($staged['nested']['label'] ?? ''));
    }
  }

}
