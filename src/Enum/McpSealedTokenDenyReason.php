<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Stable, non-secret reason codes for sealed-token authentication denials.
 *
 * Backed values are the audit_chain contract. Later slices add cases;
 * they do not rename these. There is no nbf check and no kill-switch
 * gate on verify(), so not_yet_valid and kill_blocked are not codes.
 */
enum McpSealedTokenDenyReason: string {

  // Prefix, part count, empty part, or body/claims are unusable.
  case Malformed = 'malformed';

  // HMAC over jti.body does not match the presented signature.
  case BadSignature = 'bad_signature';

  // Body exp or the stored row's expires is in the past.
  case Expired = 'expired';

  // Signature verified but no row exists for this jti.
  case UnknownToken = 'unknown_token';

  // The stored row has been revoked.
  case Revoked = 'revoked';

  // SHA-256 of the bearer does not match the stored hash.
  case HashMismatch = 'hash_mismatch';

  // The stored client_id is not in agent_oauth_clients.
  case ClientNotDesignated = 'client_not_designated';

  // Body cid/uid do not match the stored row.
  case AudienceMismatch = 'audience_mismatch';

  // The designated Consumer entity is gone.
  case ConsumerMissing = 'consumer_missing';

  // The designated Consumer is unpublished.
  case ConsumerUnpublished = 'consumer_unpublished';

  // The Consumer owner is not the uid sealed into the row.
  case OwnerMismatch = 'owner_mismatch';

  // The token owner account does not exist.
  case AccountMissing = 'account_missing';

  // The token owner account is blocked.
  case AccountBlocked = 'account_blocked';

}
