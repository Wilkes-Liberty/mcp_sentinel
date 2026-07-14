<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Validates the deny-external-redirect gate for governed agents.
 *
 * Fires a violation only when a governed agent whose resolved profile denies
 * external redirects sets a redirect whose destination is an *external* URL
 * (UrlHelper::isExternal()) pointing at a host outside the allowlist. The
 * allowlist is the profile's allowed_redirect_hosts, or — when that is empty —
 * the site's own host(s), derived from the current request host and the
 * trusted_host_patterns setting.
 *
 * The validator early-returns for every non-governed request, every profile
 * that permits external redirects, and every internal / entity: / base: /
 * relative target, so the attachment is cheap and non-external redirects are
 * never touched.
 */
final class McpDenyExternalRedirectValidator extends ConstraintValidator implements ContainerInjectionInterface {

  /**
   * Constructs the validator.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves whether the request is governed and which profile applies.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   Used to derive the current site host when the profile allowlist is empty.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly RequestStack $requestStack,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.policy_resolver'),
      $container->get('request_stack'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function validate(mixed $value, Constraint $constraint): void {
    if (!$value instanceof ContentEntityInterface || !$constraint instanceof McpDenyExternalRedirect) {
      return;
    }

    // Governance scoping — identical to the module's other gates. Ungoverned
    // (cookie-session) traffic and profiles that permit external redirects are
    // never gated here.
    if (!$this->policyResolver->isGoverned()) {
      return;
    }
    $profile = $this->policyResolver->resolve();
    if ($profile === NULL || !$profile->deniesExternalRedirects()) {
      return;
    }

    // Guard: the destination field must exist and carry a value. The redirect
    // module stores the target URI in redirect_redirect->uri.
    if (!$value->hasField('redirect_redirect') || $value->get('redirect_redirect')->isEmpty()) {
      return;
    }
    $uri = $value->get('redirect_redirect')->uri;
    if (!is_string($uri) || $uri === '') {
      return;
    }

    // internal:, entity:, base:, and relative targets are never external.
    if (!UrlHelper::isExternal($uri)) {
      return;
    }

    // The target is a full external URL. Extract its host and deny unless it is
    // on the allowlist (the profile's allowed_redirect_hosts, or the site's own
    // host(s) when the profile list is empty). A malformed external URL with no
    // parseable host fails closed and is denied.
    $host = strtolower((string) parse_url($uri, PHP_URL_HOST));
    if ($host !== '' && $this->hostIsAllowed($host, $profile->getAllowedRedirectHosts())) {
      return;
    }

    $this->context->buildViolation($constraint->message)
      ->atPath('redirect_redirect')
      ->addViolation();
  }

  /**
   * Whether an external target host is permitted.
   *
   * When the profile supplies an explicit allowlist, only those hosts (matched
   * case-insensitively) are allowed. When it is empty, the site's own host(s)
   * are the allowlist: the current request host plus any host matching a
   * configured trusted_host_patterns entry (the patterns core uses to decide
   * which Host headers belong to this site).
   *
   * @param string $host
   *   The lower-cased target host.
   * @param string[] $allowedHosts
   *   The profile's configured allowed redirect hosts (may be empty).
   *
   * @return bool
   *   TRUE if the host is on-domain / allowlisted; FALSE otherwise.
   */
  private function hostIsAllowed(string $host, array $allowedHosts): bool {
    if ($allowedHosts !== []) {
      foreach ($allowedHosts as $allowed) {
        if ($host === strtolower(trim((string) $allowed))) {
          return TRUE;
        }
      }
      return FALSE;
    }

    // Empty profile allowlist: fall back to the site's own host(s).
    $request = $this->requestStack->getCurrentRequest();
    if ($request !== NULL && $host === strtolower((string) $request->getHost())) {
      return TRUE;
    }

    // Also honor the trusted_host_patterns regexes, which define exactly which
    // Host headers core treats as belonging to this site.
    $patterns = Settings::get('trusted_host_patterns', []);
    if (is_array($patterns)) {
      foreach ($patterns as $pattern) {
        if (is_string($pattern) && $pattern !== ''
          && @preg_match('{' . $pattern . '}i', $host) === 1) {
          return TRUE;
        }
      }
    }

    return FALSE;
  }

}
