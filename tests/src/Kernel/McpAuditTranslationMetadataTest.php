<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\language\Entity\ConfigurableLanguage;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for translation identity on governed audit rows.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpAuditLogger::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpAuditTranslationMetadataTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'language',
    'content_translation',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installConfig([
      'filter',
      'node',
      'language',
      'content_translation',
      'mcp_sentinel',
    ]);

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent'])->save();
    McpPolicyProfile::create([
      'id' => 'agent_i18n',
      'label' => 'Agent i18n profile',
      'roles' => ['mcp_agent'],
      'weight' => 10,
      'allow_write' => TRUE,
    ])->save();

    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    ConfigurableLanguage::createFromLangcode('es')->save();
    $this->container->get('content_translation.manager')
      ->setEnabled('node', 'article', TRUE);
    $this->container->get('entity_type.manager')->clearCachedDefinitions();
    $this->container->get('entity_field.manager')
      ->clearCachedFieldDefinitions();
  }

  /**
   * Adding a translation stamps langcode, translation=create, and source.
   *
   * @covers ::translationMetadata
   */
  public function testTranslationCreateStampsIdentity(): void {
    $this->setGovernedCurrentUser();
    $node = $this->createEnglishArticle();
    $this->truncateLog();

    $es = $node->addTranslation('es', ['title' => 'Texto']);
    $this->container->get('content_translation.manager')
      ->getTranslationMetadata($es)
      ->setSource('en');
    $es->save();

    $meta = $this->lastEntitySaveMetadata();
    $this->assertSame('es', $meta['langcode'] ?? NULL);
    $this->assertSame('create', $meta['translation'] ?? NULL);
    $this->assertSame('en', $meta['source'] ?? NULL);
  }

  /**
   * Continuing a translation stamps langcode and omits translation=create.
   *
   * @covers ::translationMetadata
   */
  public function testTranslationContinueOmitsCreate(): void {
    $this->setGovernedCurrentUser();
    $node = $this->createEnglishArticle();
    $es = $node->addTranslation('es', ['title' => 'Texto']);
    $es->save();
    $this->truncateLog();

    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $reloaded */
    $reloaded = $storage->load($node->id());
    $again = $reloaded->getTranslation('es');
    $again->setTitle('Sobreescrito');
    $again->save();

    $meta = $this->lastEntitySaveMetadata();
    $this->assertSame('es', $meta['langcode'] ?? NULL);
    $this->assertArrayNotHasKey('translation', $meta);
  }

  /**
   * A stale-to-fresh outdated flip appears in the change diff.
   *
   * @covers ::computeChangeDiff
   */
  public function testOutdatedFlipAppearsInChanges(): void {
    $this->setGovernedCurrentUser();
    $node = $this->createEnglishArticle();
    $es = $node->addTranslation('es', ['title' => 'Texto']);
    $es->save();

    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $reloaded */
    $reloaded = $storage->load($node->id());
    $stale = $reloaded->getTranslation('es');
    if (!$stale->hasField('content_translation_outdated')) {
      $this->markTestSkipped('content_translation_outdated is not on the bundle.');
    }
    $stale->set('content_translation_outdated', TRUE);
    $stale->save();
    $this->truncateLog();

    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $fresh_host */
    $fresh_host = $storage->load($node->id());
    $fresh = $fresh_host->getTranslation('es');
    $fresh->set('content_translation_outdated', FALSE);
    $fresh->save();

    $meta = $this->lastEntitySaveMetadata();
    $this->assertArrayHasKey('changes', $meta);
    $this->assertArrayHasKey('content_translation_outdated', $meta['changes']);
    $this->assertNotSame(
      $meta['changes']['content_translation_outdated']['old'],
      $meta['changes']['content_translation_outdated']['new'],
    );
  }

  /**
   * Creates a governed user and sets it as the current user.
   */
  private function setGovernedCurrentUser(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Creates and saves an English article as the current (governed) user.
   */
  private function createEnglishArticle(): Node {
    $node = Node::create([
      'type' => 'article',
      'title' => 'English title',
      'langcode' => 'en',
    ]);
    $node->save();
    return $node;
  }

  /**
   * Truncates the audit chain so the next save is the only row.
   */
  private function truncateLog(): void {
    $this->container->get('database')
      ->truncate('audit_chain_log')
      ->execute();
  }

  /**
   * Decoded metadata of the latest entity_save row.
   *
   * @return array<string, mixed>
   *   Metadata, or empty when no row exists.
   */
  private function lastEntitySaveMetadata(): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('operation', 'entity_save')
      ->orderBy('id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row, 'An entity_save row must be written.');
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) ($row['metadata'] ?? ''));
  }

}
