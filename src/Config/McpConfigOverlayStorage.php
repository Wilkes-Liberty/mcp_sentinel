<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Config;

use Drupal\Core\Config\StorageInterface;

/**
 * Presents the active storage with one object replaced, read-only.
 *
 * Config import validators compare a source storage with the active one. To
 * run them for a single proposed write, the source is the active storage with
 * that one object swapped for the data that would be saved. Core's single
 * import form does the same with a class from the optional Config Manager
 * module; this one has no dependency on it and refuses every write, so a
 * validator cannot change the site through it.
 */
final class McpConfigOverlayStorage implements StorageInterface {

  /**
   * Constructs the overlay.
   *
   * @param \Drupal\Core\Config\StorageInterface $storage
   *   The storage to read everything else from.
   * @param string $name
   *   The replaced config object name.
   * @param array $data
   *   The data presented for that name.
   */
  public function __construct(
    private readonly StorageInterface $storage,
    private readonly string $name,
    private readonly array $data,
  ) {}

  /**
   * Whether this collection is the one the replacement applies to.
   */
  private function overlays(): bool {
    return $this->storage->getCollectionName() === StorageInterface::DEFAULT_COLLECTION;
  }

  /**
   * {@inheritdoc}
   */
  public function exists($name) {
    return ($this->overlays() && $name === $this->name) || $this->storage->exists($name);
  }

  /**
   * {@inheritdoc}
   */
  public function read($name) {
    if ($this->overlays() && $name === $this->name) {
      return $this->data;
    }
    return $this->storage->read($name);
  }

  /**
   * {@inheritdoc}
   */
  public function readMultiple(array $names) {
    $data = $this->storage->readMultiple($names);
    if ($this->overlays() && in_array($this->name, $names, TRUE)) {
      $data[$this->name] = $this->data;
    }
    return $data;
  }

  /**
   * {@inheritdoc}
   */
  public function write($name, array $data) {
    throw new \LogicException('The validation overlay storage is read-only.');
  }

  /**
   * {@inheritdoc}
   */
  public function delete($name) {
    throw new \LogicException('The validation overlay storage is read-only.');
  }

  /**
   * {@inheritdoc}
   */
  public function rename($name, $new_name) {
    throw new \LogicException('The validation overlay storage is read-only.');
  }

  /**
   * {@inheritdoc}
   */
  public function encode($data) {
    return $this->storage->encode($data);
  }

  /**
   * {@inheritdoc}
   */
  public function decode($raw) {
    return $this->storage->decode($raw);
  }

  /**
   * {@inheritdoc}
   */
  public function listAll($prefix = '') {
    $names = $this->storage->listAll($prefix);
    if ($this->overlays() && ($prefix === '' || str_starts_with($this->name, $prefix)) && !in_array($this->name, $names, TRUE)) {
      $names[] = $this->name;
      sort($names);
    }
    return $names;
  }

  /**
   * {@inheritdoc}
   */
  public function deleteAll($prefix = '') {
    throw new \LogicException('The validation overlay storage is read-only.');
  }

  /**
   * {@inheritdoc}
   */
  public function createCollection($collection) {
    // The interface documents "$this" but means a new instance for the other
    // collection, as every core storage returns.
    // @phpstan-ignore return.type
    return new self($this->storage->createCollection($collection), $this->name, $this->data);
  }

  /**
   * {@inheritdoc}
   */
  public function getAllCollectionNames() {
    return $this->storage->getAllCollectionNames();
  }

  /**
   * {@inheritdoc}
   */
  public function getCollectionName() {
    return $this->storage->getCollectionName();
  }

}
