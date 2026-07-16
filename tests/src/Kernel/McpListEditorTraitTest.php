<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Form\FormState;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Form\McpListEditorTrait;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the reusable in-form multi-row list editor trait.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
class McpListEditorTraitTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system'];

  /**
   * Builds an anonymous host class exposing the trait's helpers.
   */
  private function host(): object {
    return new class() {
      use McpListEditorTrait {
        rowCount as public;
        addRow as public;
        removeRow as public;
      }

    };
  }

  /**
   * The row count seeds to stored-items + 1 on the first build.
   */
  public function testRowCountSeedsFromStoredItemsOnFirstBuild(): void {
    $host = $this->host();
    $state = new FormState();
    // 3 stored items, no prior storage → count seeds to max(stored+1, 1).
    $this->assertSame(4, $host->rowCount($state, 'dlp_rows', 3));
  }

  /**
   * The row count persists across rebuilds, ignoring the stored-items arg.
   */
  public function testRowCountPersistsAcrossRebuilds(): void {
    $host = $this->host();
    $state = new FormState();
    $host->rowCount($state, 'dlp_rows', 3);
    // A later rebuild with the same key returns the stored count, ignoring
    // the stored-item count argument.
    $this->assertSame(4, $host->rowCount($state, 'dlp_rows', 0));
  }

  /**
   * Adding a row increments the count and decrementing never drops below one.
   */
  public function testAddAndRemoveRowAdjustCount(): void {
    $host = $this->host();
    $state = new FormState();
    $form = [];
    $host->rowCount($state, 'dlp_rows', 1);
    $host->addRow($form, $state, 'dlp_rows');
    $this->assertSame(3, $host->rowCount($state, 'dlp_rows', 0));
    $host->removeRow($form, $state, 'dlp_rows');
    $host->removeRow($form, $state, 'dlp_rows');
    $host->removeRow($form, $state, 'dlp_rows');
    // Never below one.
    $this->assertSame(1, $host->rowCount($state, 'dlp_rows', 0));
  }

}
