<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpDlp;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the DLP value-pattern masking integration.
 *
 * Verifies:
 *  - McpDlp service is instantiated correctly from config.
 *  - When DLP is enabled, an email in a governed field value is masked in
 *    the audit change-diff.
 *  - Non-governed requests produce no audit row, so DLP cannot apply.
 *  - When DLP is disabled (default), values pass through unchanged.
 *  - In partial mode, DLP keeps the last 4 chars and masks the rest.
 *
 * V1 scope: DLP is wired into the audit change-diff capture path
 * (McpAuditLogger::computeChangeDiff). GraphQL field output scanning is
 * provided by hook_graphql_compose_field_results_alter in
 * mcp_sentinel_graphql.module; that path is not exercised here because the
 * mcp_sentinel_graphql submodule depends on graphql_compose which is not
 * available in the test environment. JSON:API per-value scanning is deferred.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpDlp
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(\Drupal\mcp_sentinel\Service\McpDlp::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDlpKernelTest extends KernelTestBase {

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
    $this->installConfig(['filter', 'node', 'mcp_sentinel']);

    // Enable role-based governance fallback so tests work without an OAuth
    // token (no actual MCP server present in the kernel test environment).
    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    // Create the governed role.
    Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent'])->save();

    // Create a policy profile with write access and no field redaction.
    McpPolicyProfile::create([
      'id'              => 'agent_dlp',
      'label'           => 'Agent DLP profile',
      'roles'           => ['mcp_agent'],
      'weight'          => 10,
      'allow_write'     => TRUE,
      'redacted_fields' => [],
    ])->save();

    // Create an 'article' node type. We use the 'title' base field (always
    // present, plain string) to inject PII values, avoiding node_add_body_field
    // which is deprecated in Drupal 11.3+.
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
  }

  /**
   * Fetches all audit log rows ordered by insertion.
   *
   * @return array<int, array<string, mixed>>
   *   All rows as associative arrays.
   */
  private function fetchAuditRows(): array {
    return $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchAll(\PDO::FETCH_ASSOC);
  }

  /**
   * Decodes the metadata column of an audit row into an array.
   *
   * @param array<string, mixed> $row
   *   The audit row.
   *
   * @return array<string, mixed>
   *   Decoded metadata.
   */
  private function decodeMetadata(array $row): array {
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) ($row['metadata'] ?? ''));
  }

  /**
   * Sets a governed user as the current user.
   */
  private function setGovernedCurrentUser(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Sets a non-governed user as the current user.
   */
  private function setUngoverned(): void {
    $account = $this->createUser();
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Enables DLP with the built-in patterns in redact mode and rebuilds the DI.
   */
  private function enableDlpRedact(): void {
    $this->config('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_mask_mode', 'redact')
      ->set('dlp_patterns', McpDlp::defaultPatterns())
      ->save();
    // Rebuild the service container so the McpDlp factory reads the new config.
    $this->container->get('kernel')->rebuildContainer();
    // @phpstan-ignore assign.propertyType
    $this->container = $this->container->get('kernel')->getContainer();
  }

  /**
   * Enables DLP with the built-in patterns in partial mode and rebuilds the DI.
   */
  private function enableDlpPartial(): void {
    $this->config('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_mask_mode', 'partial')
      ->set('dlp_patterns', McpDlp::defaultPatterns())
      ->save();
    $this->container->get('kernel')->rebuildContainer();
    // @phpstan-ignore assign.propertyType
    $this->container = $this->container->get('kernel')->getContainer();
  }

  /**
   * The mcp_sentinel.dlp service is registered and returns an McpDlp instance.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpDlp::createFromConfig
   */
  public function testDlpServiceIsRegistered(): void {
    $dlp = $this->container->get('mcp_sentinel.dlp');
    // Confirm the service is wired; scan() being callable is sufficient proof.
    // @phpstan-ignore method.alreadyNarrowedType
    $this->assertNotNull($dlp);
    $this->assertSame('', $dlp->scan(''));
  }

  /**
   * When DLP is disabled (the default), scan() is a no-op.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpDlp::scan
   */
  public function testDlpDisabledByDefault(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpDlp $dlp */
    $dlp = $this->container->get('mcp_sentinel.dlp');
    $this->assertSame(
      'user@example.com',
      $dlp->scan('user@example.com'),
      'DLP is off by default; email must pass through unchanged.',
    );
  }

  /**
   * When DLP is enabled, an email embedded in the title is masked in the diff.
   *
   * A governed agent updates a node title that contains an email address.
   * The change-diff entry for 'title' must not contain the raw email — it
   * must contain '[REDACTED]' instead.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpDlp::scan
   */
  public function testDlpMasksEmailInAuditDiff(): void {
    $this->enableDlpRedact();
    $this->setGovernedCurrentUser();

    // Create a node with a neutral title.
    $node = Node::create([
      'type'  => 'article',
      'title' => 'Contact us',
    ]);
    $node->save();

    $this->container->get('database')
      ->truncate('audit_chain_log')
      ->execute();

    // Update the title to include an email address.
    $node->setTitle('Contact admin@example.com for help');
    $node->save();

    $rows = $this->fetchAuditRows();
    $this->assertNotEmpty($rows, 'An audit row must be written on a governed update.');

    $meta = $this->decodeMetadata(end($rows));
    $this->assertArrayHasKey('changes', $meta, "'changes' key must be present for a governed update.");

    $changes = $meta['changes'];
    $this->assertArrayHasKey('title', $changes, "'title' must appear in the change diff.");

    // The new value must not contain the raw email.
    $this->assertStringNotContainsString(
      'admin@example.com',
      $changes['title']['new'],
      'Raw email must not appear in the audit change-diff new value.',
    );
    // It must contain the redaction marker.
    $this->assertStringContainsString(
      '[REDACTED]',
      $changes['title']['new'],
      'Redacted placeholder must appear in the audit change-diff new value.',
    );
    // The surrounding text must be preserved.
    $this->assertStringContainsString('Contact', $changes['title']['new']);
  }

  /**
   * In partial mode, an email in the change-diff is partially masked.
   *
   * The last 4 chars of the email match ('.com') are kept; the rest is '*'.
   * '[REDACTED]' must NOT appear.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpDlp::scan
   */
  public function testDlpPartialMaskInAuditDiff(): void {
    $this->enableDlpPartial();
    $this->setGovernedCurrentUser();

    $node = Node::create([
      'type'  => 'article',
      'title' => 'Old title',
    ]);
    $node->save();

    $this->container->get('database')
      ->truncate('audit_chain_log')
      ->execute();

    $node->setTitle('Email test@example.com is here');
    $node->save();

    $rows = $this->fetchAuditRows();
    $this->assertNotEmpty($rows);

    $meta = $this->decodeMetadata(end($rows));
    $this->assertArrayHasKey('changes', $meta);

    $new_title = $meta['changes']['title']['new'] ?? '';
    // Partial mode: no [REDACTED], no raw email local-part.
    $this->assertStringNotContainsString('[REDACTED]', $new_title);
    $this->assertStringNotContainsString('test@', $new_title);
    // The last 4 chars of the match '.com' must be present.
    $this->assertStringContainsString('.com', $new_title);
    // The surrounding text is preserved.
    $this->assertStringContainsString('Email', $new_title);
  }

  /**
   * Non-governed updates do NOT produce an audit row, so DLP does not apply.
   *
   * The presave hook only fires for governed requests; a non-governed save
   * produces no audit row. This also verifies the boundary: an ungoverned
   * user can save a node with PII in the title without any masking or audit.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpDlp::scan
   */
  public function testDlpNotAppliedForNonGovernedRequest(): void {
    $this->enableDlpRedact();
    $this->setUngoverned();

    // Non-governed save: should produce no audit row.
    $node = Node::create([
      'type'  => 'article',
      'title' => 'Ungoverned node',
    ]);
    $node->save();

    $this->container->get('database')
      ->truncate('audit_chain_log')
      ->execute();

    $node->setTitle('Ungoverned update with user@example.com');
    $node->save();

    $rows = $this->fetchAuditRows();
    $this->assertEmpty(
      $rows,
      'No audit row must be written for non-governed updates.',
    );
  }

  /**
   * When DLP is disabled, raw email values appear unmasked in the audit diff.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpDlp::scan
   */
  public function testDlpDisabledDoesNotMaskAuditDiff(): void {
    // Ensure DLP is explicitly off.
    $this->config('mcp_sentinel.settings')
      ->set('dlp_enabled', FALSE)
      ->save();

    $this->setGovernedCurrentUser();

    $node = Node::create([
      'type'  => 'article',
      'title' => 'Original title',
    ]);
    $node->save();

    $this->container->get('database')
      ->truncate('audit_chain_log')
      ->execute();

    $node->setTitle('Contact dlpoff@example.com');
    $node->save();

    $rows = $this->fetchAuditRows();
    $this->assertNotEmpty($rows);

    $meta = $this->decodeMetadata(end($rows));
    $changes = $meta['changes'] ?? [];
    $new_title = $changes['title']['new'] ?? '';
    // DLP off: the raw email must appear in the diff.
    $this->assertStringContainsString(
      'dlpoff@example.com',
      $new_title,
      'DLP is disabled; the raw email must appear in the audit change-diff.',
    );
  }

  /**
   * Fix C: custom patterns saved as dlp_patterns config are honoured by scan().
   *
   * Saves a custom pattern directly into config (mimicking what the settings
   * form submitForm() now does) and verifies that McpDlp picks it up after a
   * container rebuild.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpDlp::scan
   */
  public function testCustomPatternPersistsAndIsApplied(): void {
    // Store a custom pattern via config (as the form would do).
    $this->config('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_mask_mode', 'redact')
      ->set('dlp_patterns', [
        [
          'label' => 'employee_id',
          'regex' => 'EMP-\d{6}',
          'mask'  => '*',
        ],
      ])
      ->save();
    $this->container->get('kernel')->rebuildContainer();
    // @phpstan-ignore assign.propertyType
    $this->container = $this->container->get('kernel')->getContainer();

    /** @var \Drupal\mcp_sentinel\Service\McpDlp $dlp */
    $dlp = $this->container->get('mcp_sentinel.dlp');

    // The custom pattern must fire.
    $this->assertSame('[REDACTED]', $dlp->scan('EMP-123456'));
    // The default email pattern must NOT fire because we replaced the patterns.
    $this->assertSame(
      'user@example.com',
      $dlp->scan('user@example.com'),
      'Custom patterns replace defaults; the email pattern must not apply.',
    );
  }

  /**
   * Fix C: an empty dlp_patterns list falls back to the default patterns.
   *
   * When the operator saves an empty textarea, dlp_patterns is stored as []
   * and createFromConfig() must fall back to defaultPatterns().
   *
   * @covers \Drupal\mcp_sentinel\Service\McpDlp::scan
   */
  public function testEmptyPatternsConfigFallsBackToDefaults(): void {
    $this->config('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_mask_mode', 'redact')
      ->set('dlp_patterns', [])
      ->save();
    $this->container->get('kernel')->rebuildContainer();
    // @phpstan-ignore assign.propertyType
    $this->container = $this->container->get('kernel')->getContainer();

    /** @var \Drupal\mcp_sentinel\Service\McpDlp $dlp */
    $dlp = $this->container->get('mcp_sentinel.dlp');

    // Fallback to defaults: the email pattern must be active.
    $this->assertSame('[REDACTED]', $dlp->scan('user@example.com'));
  }

  /**
   * ComputeChangeDiff() with an active McpDlp masks emails in returned values.
   *
   * Exercises the DLP path directly (no full presave), verifying that
   * McpAuditLogger::computeChangeDiff() delegates to McpDlp for non-redacted
   * field values.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpAuditLogger::computeChangeDiff
   */
  public function testComputeChangeDiffAppliesDlp(): void {
    $this->enableDlpRedact();

    $logger = $this->container->get('mcp_sentinel.audit_logger');

    $node = Node::create([
      'type'  => 'article',
      'title' => 'Before no email',
    ]);
    $node->enforceIsNew(FALSE);
    $node->set('nid', 888);

    $original = Node::create([
      'type'  => 'article',
      'title' => 'Before no email',
    ]);
    $original->enforceIsNew(FALSE);
    $original->set('nid', 888);
    // setOriginal() arrived in Drupal 11.2; below that (10.6, 11.0, 11.1) the
    // magic property it replaced is the only way in.
    if (method_exists($node, 'setOriginal')) {
      $node->setOriginal($original);
    }
    else {
      $node->original = $original;
    }

    // Change the title to include a PII email address.
    $node->setTitle('Contact secret@example.com now');

    $diff = $logger->computeChangeDiff($node, []);

    $this->assertArrayHasKey('title', $diff);
    // Old value: no PII, passes through unchanged.
    $this->assertSame('Before no email', $diff['title']['old']);
    // New value: email must be redacted.
    $this->assertStringNotContainsString(
      'secret@example.com',
      $diff['title']['new'],
      'DLP must mask the email in the new title value.',
    );
    $this->assertStringContainsString('[REDACTED]', $diff['title']['new']);
    $this->assertStringContainsString('Contact', $diff['title']['new']);
  }

}
