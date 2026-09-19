<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ConfigImporter;
use Drupal\Core\Config\ConfigImporterException;
use Drupal\Core\Config\ConfigManagerInterface;
use Drupal\Core\Config\StorageComparer;
use Drupal\Core\Config\StorageInterface;
use Drupal\Core\Config\TypedConfigManagerInterface;
use Drupal\Core\Extension\ModuleExtensionList;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Extension\ModuleInstallerInterface;
use Drupal\Core\Extension\ThemeExtensionList;
use Drupal\Core\Extension\ThemeHandlerInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\StringTranslation\TranslationInterface;
use Drupal\mcp_sentinel\Config\McpConfigOverlayStorage;
use Drupal\mcp_sentinel\Value\McpConfigWriteVerdict;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Validates a governed config write before anything is stored or queued.
 *
 * A governed agent's write does not pass through a settings form or a config
 * import, which is where most modules validate their settings. This service
 * runs the two checks that a config import of the same values would run:
 *
 * 1. Typed-config validation of the merged object (types, schema constraints,
 *    unknown keys). Any violation refuses the write.
 * 2. The config import validators, against the active storage with only this
 *    object replaced. Core's single-object import form validates the same way.
 *    Nothing is imported: ConfigImporter::validate() only dispatches the event.
 *
 * A name with no schema cannot be checked at all, so it is refused unless the
 * caller passes the resolved profile's explicit opt-in.
 *
 * The check is strict about the whole object. If the active data already
 * violates its schema, a write to another key is refused too, and the returned
 * paths name what must be fixed first.
 *
 * The import validators read the whole active configuration twice to build
 * their change list. That cost is paid once per governed write, which is
 * rate-limited and rare.
 */
final class McpConfigWriteValidator {

  /**
   * How many property paths a verdict reports.
   */
  private const MAX_PATHS = 20;

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TypedConfigManagerInterface $typedConfig,
    private readonly StorageInterface $activeStorage,
    private readonly EventDispatcherInterface $eventDispatcher,
    private readonly ConfigManagerInterface $configManager,
    private readonly LockBackendInterface $lock,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly ModuleInstallerInterface $moduleInstaller,
    private readonly ThemeHandlerInterface $themeHandler,
    private readonly TranslationInterface $stringTranslation,
    private readonly ModuleExtensionList $moduleExtensionList,
    private readonly ThemeExtensionList $themeExtensionList,
    private readonly LoggerChannelInterface $logger,
  ) {}

  /**
   * Validates the object that writing these keys would produce.
   *
   * @param string $name
   *   The config object name.
   * @param array $data
   *   The keys to set, as the config set tool receives them.
   * @param bool $allowSchemaless
   *   The resolved profile's opt-in for names that have no schema.
   *
   * @return \Drupal\mcp_sentinel\Value\McpConfigWriteVerdict
   *   Valid, or refused with a reason code and property paths. Never values.
   */
  public function validate(string $name, array $data, bool $allowSchemaless): McpConfigWriteVerdict {
    try {
      // Work on a clone. The factory keeps the mutable object it hands out
      // in its static cache, so setting keys on that one would leave unsaved
      // values behind for the rest of the request, and the next save of this
      // name by anyone would persist a change that was refused here.
      $proposed = clone $this->configFactory->getEditable($name);
      foreach ($data as $key => $value) {
        $proposed->set((string) $key, $value);
      }
      $merged = $proposed->getRawData();
    }
    catch (\Throwable $e) {
      $this->logFailure('merge', $name, $e);
      return McpConfigWriteVerdict::refused(McpConfigWriteVerdict::INVALID_STRUCTURE);
    }

    try {
      $schemaless = !$this->typedConfig->hasConfigSchema($name);
      if ($schemaless && !$allowSchemaless) {
        return McpConfigWriteVerdict::refused(McpConfigWriteVerdict::SCHEMA_MISSING);
      }
      if (!$schemaless) {
        $paths = [];
        foreach ($this->typedConfig->createFromNameAndData($name, $merged)->validate() as $violation) {
          $paths[$this->safePath((string) $violation->getPropertyPath())] = TRUE;
        }
        if ($paths !== []) {
          ksort($paths);
          return McpConfigWriteVerdict::refused(
            McpConfigWriteVerdict::SCHEMA_VIOLATION,
            array_slice(array_keys($paths), 0, self::MAX_PATHS),
          );
        }
      }
    }
    catch (\Throwable $e) {
      $this->logFailure('schema', $name, $e);
      return McpConfigWriteVerdict::refused(McpConfigWriteVerdict::VALIDATION_ERROR);
    }

    $importErrors = $this->importValidatorErrors($name, $merged);
    if ($importErrors === NULL) {
      return McpConfigWriteVerdict::refused(McpConfigWriteVerdict::VALIDATION_ERROR);
    }
    if ($importErrors > 0) {
      return McpConfigWriteVerdict::refused(McpConfigWriteVerdict::IMPORT_VALIDATION, [], $importErrors);
    }
    return McpConfigWriteVerdict::valid($schemaless);
  }

  /**
   * Runs the config import validators for this one object.
   *
   * @return int|null
   *   The number of errors they logged, or NULL when they could not run.
   */
  private function importValidatorErrors(string $name, array $merged): ?int {
    try {
      $comparer = new StorageComparer(
        new McpConfigOverlayStorage($this->activeStorage, $name, $merged),
        $this->activeStorage,
      );
      if (!$comparer->createChangelist()->hasChanges()) {
        return 0;
      }
      $importer = new ConfigImporter(
        $comparer,
        $this->eventDispatcher,
        $this->configManager,
        $this->lock,
        $this->typedConfig,
        $this->moduleHandler,
        $this->moduleInstaller,
        $this->themeHandler,
        $this->stringTranslation,
        $this->moduleExtensionList,
        $this->themeExtensionList,
      );
      try {
        $importer->validate();
      }
      catch (ConfigImporterException) {
        // The errors are counted below. Their text is not used: a validator
        // may repeat the staged value in it.
      }
      return count($importer->getErrors());
    }
    catch (\Throwable $e) {
      $this->logFailure('import validators', $name, $e);
      return NULL;
    }
  }

  /**
   * Reduces a property path to key characters and a bounded length.
   *
   * A path is made of config keys, and a sequence key can be caller data.
   */
  private function safePath(string $path): string {
    $path = (string) preg_replace('/[^A-Za-z0-9_.:\-]/', '_', $path);
    return $path === '' ? '(root)' : substr($path, 0, 128);
  }

  /**
   * Logs which stage failed and the exception class, never its message.
   */
  private function logFailure(string $stage, string $name, \Throwable $e): void {
    $this->logger->error('Config write validation (@stage) could not run for @name: @type at @file:@line.', [
      '@stage' => $stage,
      '@name' => $name,
      '@type' => get_class($e),
      '@file' => basename($e->getFile()),
      '@line' => $e->getLine(),
    ]);
  }

}
