<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface;
use Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Writes one sealed-token denial to audit_chain, with bounded flood safety.
 *
 * Denials stay fail-closed: a write or dedupe failure never becomes an
 * allow. Repeat denials of the same reason, principal, and source
 * inside one time window share a single chain row. The window is
 * {@see self::DEFAULT_WINDOW} seconds unless
 * mcp_sentinel.settings:sealed_token_deny_audit_window is a value in
 * 1..3600.
 *
 * @internal
 */
final class McpSealedTokenDenialAuditor {

  /**
   * Default aggregation window, in seconds.
   */
  public const DEFAULT_WINDOW = 60;

  /**
   * Maximum configurable window, in seconds.
   */
  public const MAX_WINDOW = 3600;

  /**
   * Key-value collection for the in-window denial bucket.
   */
  public const KV_COLLECTION = 'mcp_sentinel.sealed_token_deny';

  /**
   * Hex length of a token SHA-256 prefix when no jti is known.
   */
  public const HASH_PREFIX_LENGTH = 12;

  /**
   * Audit metadata keys that may be stored. Everything else is dropped.
   *
   * @var list<string>
   */
  private const CONTEXT_KEYS = [
    'jti',
    'uid',
    'client_id',
    'path',
    'site',
    'token_hash_prefix',
  ];

  /**
   * Constructs the auditor.
   */
  public function __construct(
    private readonly McpAuditLogger $auditLogger,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
    private readonly RequestStack $requestStack,
    private readonly LoggerInterface $logger,
    private readonly KeyValueExpirableFactoryInterface $keyValueFactory,
  ) {}

  /**
   * Records one sealed-token denial without throwing to the caller.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason $reason
   *   Enumerated denial reason.
   * @param array<string, mixed> $context
   *   Non-secret context. Unknown keys, the bearer, and signatures
   *   are discarded.
   */
  public function record(McpSealedTokenDenyReason $reason, array $context = []): void {
    $context = $this->allowedContext($context);
    $metadata = $this->metadata($reason, $context);
    try {
      if ($this->inWindow($reason, $metadata)) {
        return;
      }
    }
    catch (\Throwable $exception) {
      $this->logger->error(
        'Sealed-token denial audit dedupe failed with @class.',
        ['@class' => $exception::class],
      );
    }
    try {
      $this->auditLogger->logAlways('denied_access', $metadata);
    }
    catch (\Throwable $exception) {
      $this->logger->error(
        'Sealed-token denial audit write failed with @class.',
        ['@class' => $exception::class],
      );
      return;
    }
    try {
      $this->remember($reason, $metadata);
    }
    catch (\Throwable $exception) {
      $this->logger->error(
        'Sealed-token denial audit dedupe failed with @class.',
        ['@class' => $exception::class],
      );
    }
  }

  /**
   * Keeps only non-secret, enumerated context keys.
   *
   * @param array<string, mixed> $context
   *   Caller-supplied context. Token, signature, and unknown keys
   *   are dropped.
   *
   * @return array<string, mixed>
   *   Filtered context.
   */
  private function allowedContext(array $context): array {
    $allowed = [];
    foreach (self::CONTEXT_KEYS as $key) {
      if (array_key_exists($key, $context)) {
        $allowed[$key] = $context[$key];
      }
    }
    return $allowed;
  }

  /**
   * Builds the audit metadata payload.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason $reason
   *   Enumerated denial reason.
   * @param array<string, mixed> $context
   *   Caller-supplied non-secret context.
   *
   * @return array<string, mixed>
   *   Metadata written to the chain.
   */
  private function metadata(McpSealedTokenDenyReason $reason, array $context): array {
    $request = $this->requestStack->getCurrentRequest();
    $path = $this->boundedString($context['path'] ?? NULL);
    if ($path === '' && $request !== NULL) {
      $path = $this->boundedString($request->getPathInfo());
    }
    $site = $this->boundedString($context['site'] ?? NULL);
    if ($site === '' && $request !== NULL) {
      $site = $this->boundedString($request->getHost());
    }
    if ($site === '') {
      $site = $this->boundedString(
        $this->configFactory->get('system.site')->get('name'),
      );
    }

    $metadata = [
      'tool' => 'sealed_token',
      'reason' => $this->reasonCode($reason),
      'window_seconds' => $this->window(),
      'count' => 1,
    ];
    $jti = $this->boundedString($context['jti'] ?? NULL);
    if ($jti !== '') {
      $metadata['jti'] = $jti;
    }
    $prefix = $this->boundedString($context['token_hash_prefix'] ?? NULL);
    if ($jti === '' && $prefix !== '') {
      $metadata['token_hash_prefix'] = substr(
        $prefix,
        0,
        self::HASH_PREFIX_LENGTH,
      );
    }
    if (isset($context['uid']) && is_numeric($context['uid'])) {
      $metadata['uid'] = (int) $context['uid'];
    }
    $clientId = $this->boundedString($context['client_id'] ?? NULL);
    if ($clientId !== '') {
      $metadata['client_id'] = $clientId;
    }
    if ($site !== '') {
      $metadata['site'] = $site;
    }
    if ($path !== '') {
      $metadata['path'] = $path;
    }
    return $metadata;
  }

  /**
   * Backed reason code. Exhaustive so a new case cannot ship unaudited.
   */
  private function reasonCode(McpSealedTokenDenyReason $reason): string {
    return match ($reason) {
      McpSealedTokenDenyReason::Malformed,
      McpSealedTokenDenyReason::BadSignature,
      McpSealedTokenDenyReason::Expired,
      McpSealedTokenDenyReason::UnknownToken,
      McpSealedTokenDenyReason::Revoked,
      McpSealedTokenDenyReason::HashMismatch,
      McpSealedTokenDenyReason::ClientNotDesignated,
      McpSealedTokenDenyReason::AudienceMismatch,
      McpSealedTokenDenyReason::ConsumerMissing,
      McpSealedTokenDenyReason::ConsumerUnpublished,
      McpSealedTokenDenyReason::OwnerMismatch,
      McpSealedTokenDenyReason::AccountMissing,
      McpSealedTokenDenyReason::AccountBlocked => $reason->value,
    };
  }

  /**
   * Whether this denial already has a chain row in the current window.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason $reason
   *   Enumerated denial reason.
   * @param array<string, mixed> $metadata
   *   Metadata that will be (or was) written.
   *
   * @return bool
   *   TRUE when a further chain write should be skipped.
   */
  private function inWindow(McpSealedTokenDenyReason $reason, array $metadata): bool {
    $store = $this->store();
    $key = $this->bucketKey($reason, $metadata);
    $entry = $store->get($key);
    if (!is_array($entry)) {
      return FALSE;
    }
    $entry['count'] = (int) ($entry['count'] ?? 1) + 1;
    $store->setWithExpire($key, $entry, $this->window());
    return TRUE;
  }

  /**
   * Records that this window now has a chain row.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason $reason
   *   Enumerated denial reason.
   * @param array<string, mixed> $metadata
   *   Metadata that was written.
   */
  private function remember(McpSealedTokenDenyReason $reason, array $metadata): void {
    $this->store()->setWithExpire(
      $this->bucketKey($reason, $metadata),
      ['count' => 1],
      $this->window(),
    );
  }

  /**
   * Bucket key for reason + principal + source + window.
   *
   * Random tokens do not get their own rows: the flood case is many
   * distinct bearers of the same reason from the same caller path.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason $reason
   *   Enumerated denial reason.
   * @param array<string, mixed> $metadata
   *   Metadata used for principal and source.
   *
   * @return string
   *   Key-value key.
   */
  private function bucketKey(McpSealedTokenDenyReason $reason, array $metadata): string {
    $principal = isset($metadata['uid']) ? (string) (int) $metadata['uid'] : '-';
    $source = (string) ($metadata['site'] ?? '-')
      . '|'
      . (string) ($metadata['path'] ?? '-');
    $window = $this->window();
    $bucket = intdiv($this->time->getRequestTime(), $window);
    return hash(
      'sha256',
      $reason->value . "\0" . $principal . "\0" . $source . "\0" . (string) $bucket,
    );
  }

  /**
   * Configured aggregation window, or the safe default.
   */
  private function window(): int {
    $raw = $this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('sealed_token_deny_audit_window');
    $window = is_numeric($raw) ? (int) $raw : self::DEFAULT_WINDOW;
    if ($window < 1 || $window > self::MAX_WINDOW) {
      return self::DEFAULT_WINDOW;
    }
    return $window;
  }

  /**
   * Expirable store for denial buckets.
   */
  private function store(): KeyValueStoreExpirableInterface {
    return $this->keyValueFactory->get(self::KV_COLLECTION);
  }

  /**
   * Returns a bounded UTF-8 string, or empty when unusable.
   *
   * @param mixed $value
   *   Raw value.
   *
   * @return string
   *   At most 256 characters, never a secret-looking blob.
   */
  private function boundedString(mixed $value): string {
    if (!is_string($value) && !is_int($value)) {
      return '';
    }
    return mb_strcut(mb_scrub((string) $value, 'UTF-8'), 0, 256, 'UTF-8');
  }

}
