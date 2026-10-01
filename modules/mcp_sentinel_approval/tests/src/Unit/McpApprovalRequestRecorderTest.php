<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Unit;

use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\mcp_sentinel_approval\Service\McpApprovalRequestRecorder;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Pending approval-request insert used by both destructive subscribers.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_approval\Service\McpApprovalRequestRecorder
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpApprovalRequestRecorder::class)]
#[Group('mcp_sentinel')]
final class McpApprovalRequestRecorderTest extends UnitTestCase {

  /**
   * A successful insert returns the saved request.
   *
   * @covers ::record
   */
  public function testRecordReturnsSavedRequest(): void {
    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn(4);

    $request = $this->createMock(McpApprovalRequestInterface::class);
    $request->expects($this->once())->method('save');
    $request->method('id')->willReturn('12');

    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->expects($this->once())
      ->method('create')
      ->with($this->callback(static function (array $values): bool {
        return $values['requested_by'] === 4
          && $values['operation'] === 'delete'
          && $values['entity_type'] === 'node'
          && $values['entity_id'] === '9'
          && $values['status'] === McpApprovalRequestInterface::STATUS_PENDING
          && $values['manifest'] === ''
          && $values['payload'] === '{"entity_id":"9"}';
      }))
      ->willReturn($request);

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')
      ->with('mcp_approval_request')
      ->willReturn($storage);

    $logger = $this->createMock(LoggerChannelInterface::class);
    $logger->expects($this->never())->method('error');

    $recorder = new McpApprovalRequestRecorder($entityTypeManager, $logger);
    $saved = $recorder->record(
      $account,
      'delete',
      'node',
      '9',
      ['entity_id' => '9'],
      NULL,
    );
    $this->assertSame($request, $saved);
    $this->assertSame('12', (string) $saved->id());
  }

  /**
   * A storage failure is logged and returns NULL so the caller still vetoes.
   *
   * @covers ::record
   */
  public function testRecordFailureLogsAndReturnsNull(): void {
    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn(4);

    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('create')
      ->willThrowException(new \RuntimeException('disk full'));

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('getStorage')
      ->with('mcp_approval_request')
      ->willReturn($storage);

    $logger = $this->createMock(LoggerChannelInterface::class);
    $logger->expects($this->once())->method('error');

    $recorder = new McpApprovalRequestRecorder($entityTypeManager, $logger);
    $this->assertNull($recorder->record(
      $account,
      'delete',
      'node',
      '9',
      ['entity_id' => '9'],
      NULL,
    ));
  }

}
