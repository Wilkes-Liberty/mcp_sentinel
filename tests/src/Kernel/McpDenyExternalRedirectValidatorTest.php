<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\redirect\Entity\Redirect;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the deny-external-redirect validation constraint.
 *
 * The McpDenyExternalRedirect constraint is the open-redirect / phishing gate.
 * It is attached to the redirect entity type (guarded on the redirect module
 * being installed) and enforced when the entity is validated — the seam
 * JSON:API and REST use before a write, and the only layer that sees the
 * incoming destination URI. A governed agent whose profile denies external
 * redirects may not point a redirect off-domain; internal, entity:, base:, and
 * relative targets are always permitted.
 *
 * These tests drive the constraint through $entity->validate() and assert only
 * on the constraint's own message so unrelated core violations never mask the
 * result.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDenyExternalRedirectValidatorTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'link',
    'path_alias',
    'serialization',
    'tool',
    'key',
    'consumers',
    'simple_oauth',
    'encrypt',
    'redirect',
    'mcp_sentinel',
  ];

  /**
   * The exact off-domain denial message the constraint emits.
   */
  private const DENY_MESSAGE = 'Redirecting to an external domain is denied by MCP Sentinel.';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
    ]);
    $this->installEntitySchema('user');
    $this->installEntitySchema('redirect');
    $this->installConfig(['system', 'user', 'field', 'redirect', 'mcp_sentinel']);

    // Governed role with the context permission.
    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    // Enable role-fallback governance for the mcp_api role.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    // Content tier: writes allowed, external redirects denied (default TRUE).
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->set('deny_external_redirects', TRUE)
      ->set('allowed_redirect_hosts', [])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
  }

  /**
   * Returns a governed mcp_api account set as the current user.
   */
  private function createGovernedAccount(): AccountInterface {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * Builds an (unsaved) redirect whose destination URI is exactly $uri.
   */
  private function makeRedirect(string $uri): Redirect {
    $redirect = Redirect::create();
    $redirect->setSource('from-' . substr(md5($uri), 0, 8));
    $redirect->set('redirect_redirect', ['uri' => $uri]);
    return $redirect;
  }

  /**
   * Whether the entity's violations include the deny-external-redirect message.
   */
  private function hasDenyViolation(Redirect $redirect): bool {
    foreach ($redirect->validate() as $violation) {
      if ((string) $violation->getMessage() === self::DENY_MESSAGE) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * A governed agent may not point a redirect at an external host.
   */
  public function testExternalTargetDenied(): void {
    $this->createGovernedAccount();
    $redirect = $this->makeRedirect('https://evil.example/login');
    $this->assertTrue($this->hasDenyViolation($redirect),
      'A governed agent must not be able to redirect off-domain.');
  }

  /**
   * An internal target is never external and is always allowed.
   */
  public function testInternalTargetAllowed(): void {
    $this->createGovernedAccount();
    $redirect = $this->makeRedirect('internal:/node/1');
    $this->assertFalse($this->hasDenyViolation($redirect),
      'An internal redirect target must be allowed.');
  }

  /**
   * An entity: target is never external and is always allowed.
   */
  public function testEntityTargetAllowed(): void {
    $this->createGovernedAccount();
    $redirect = $this->makeRedirect('entity:node/1');
    $this->assertFalse($this->hasDenyViolation($redirect),
      'An entity: redirect target must be allowed.');
  }

  /**
   * An external target on the profile allowlist is permitted.
   */
  public function testAllowlistedExternalHostAllowed(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allowed_redirect_hosts', ['docs.example.com'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $this->createGovernedAccount();
    $allowed = $this->makeRedirect('https://docs.example.com/guide');
    $this->assertFalse($this->hasDenyViolation($allowed),
      'An allowlisted external host must be permitted.');

    // A different external host is still denied even with an allowlist set.
    $denied = $this->makeRedirect('https://evil.example/login');
    $this->assertTrue($this->hasDenyViolation($denied),
      'A host outside the allowlist must still be denied.');
  }

  /**
   * With an empty allowlist, the site's own host is treated as on-domain.
   */
  public function testSiteOwnHostAllowed(): void {
    $this->createGovernedAccount();
    $host = \Drupal::request()->getHost();
    $redirect = $this->makeRedirect('https://' . $host . '/somewhere');
    $this->assertFalse($this->hasDenyViolation($redirect),
      "The site's own host ({$host}) must be treated as on-domain.");
  }

  /**
   * An ungoverned (human) account is never gated by the redirect constraint.
   */
  public function testNonGovernedAccountNotGated(): void {
    $ungoverned = $this->createUser();
    \Drupal::currentUser()->setAccount($ungoverned);

    $redirect = $this->makeRedirect('https://evil.example/login');
    $this->assertFalse($this->hasDenyViolation($redirect),
      'An ungoverned account must not be gated by the redirect constraint.');
  }

  /**
   * A profile that permits external redirects does not fire the gate.
   */
  public function testAllowExternalProfileNotGated(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('deny_external_redirects', FALSE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $this->createGovernedAccount();
    $redirect = $this->makeRedirect('https://evil.example/login');
    $this->assertFalse($this->hasDenyViolation($redirect),
      'A profile that permits external redirects must not fire the gate.');
  }

}
