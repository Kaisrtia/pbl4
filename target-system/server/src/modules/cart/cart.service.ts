import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { DatabaseService } from '../../database/database.service';
import type { CartProductItem, CartSummary } from '@shared/schemas/shop-api';

export type { CartProductItem, CartSummary };

@Injectable()
export class CartService {
  private readonly logger = new Logger(CartService.name);

  constructor(private readonly db: DatabaseService) {}

  /**
   * Lấy thông tin giỏ hàng hiện tại (Tổng số lượng món cho Badge và danh sách chi tiết)
   */
  getCart(
    sessionId: string = 'demo-guest-session-pbl4',
    userId?: number,
  ): CartSummary {
    const rows = this.db.query(
      `
      SELECT 
        ci.id,
        ci.product_id,
        ci.quantity,
        p.sku,
        p.name,
        p.brand,
        p.price,
        p.stock,
        p.image_url,
        (ci.quantity * p.price) as subtotal
      FROM cart_items ci
      JOIN products p ON ci.product_id = p.id
      WHERE ci.session_id = ? OR (ci.user_id IS NOT NULL AND ci.user_id = ?)
      ORDER BY ci.id ASC
    `,
      [sessionId, userId ?? -1],
    );

    const items: CartProductItem[] = rows.map((r: any) => ({
      id: r.id,
      product_id: r.product_id,
      sku: r.sku,
      name: r.name,
      brand: r.brand,
      price: r.price,
      stock: r.stock,
      image_url: r.image_url,
      quantity: r.quantity,
      subtotal: r.subtotal,
    }));

    const totalItems = items.reduce((sum, item) => sum + item.quantity, 0);
    const totalPrice = items.reduce((sum, item) => sum + item.subtotal, 0);

    return {
      total_items: totalItems,
      total_price: totalPrice,
      items,
    };
  }

  /**
   * Thêm sản phẩm vào giỏ hàng
   */
  addItem(
    productId: number,
    quantity: number = 1,
    sessionId: string = 'demo-guest-session-pbl4',
    userId?: number,
  ): CartSummary {
    if (quantity <= 0) {
      throw new BadRequestException(
        'Số lượng thêm vào giỏ hàng phải lớn hơn 0',
      );
    }

    // 1. Kiểm tra sản phẩm có tồn tại trong kho không
    const products = this.db.query(
      'SELECT id, name, stock FROM products WHERE id = ?',
      [productId],
    );
    if (!products || products.length === 0) {
      throw new NotFoundException(
        `Không tìm thấy sản phẩm có ID [${productId}]`,
      );
    }

    const product = products[0];

    // 2. Kiểm tra xem sản phẩm đã có trong giỏ hàng của session này chưa
    const existing = this.db.query(
      `
      SELECT id, quantity FROM cart_items 
      WHERE product_id = ? AND (session_id = ? OR (user_id IS NOT NULL AND user_id = ?))
    `,
      [productId, sessionId, userId ?? -1],
    );

    if (existing && existing.length > 0) {
      // Đã có -> cộng dồn số lượng
      const newQuantity = existing[0].quantity + quantity;
      this.db.query('UPDATE cart_items SET quantity = ? WHERE id = ?', [
        newQuantity,
        existing[0].id,
      ]);
      this.logger.log(
        `[CART] Incremented quantity for product [${product.name}] to ${newQuantity}`,
      );
    } else {
      // Chưa có -> thêm mới
      this.db.query(
        `
        INSERT INTO cart_items (user_id, session_id, product_id, quantity)
        VALUES (?, ?, ?, ?)
      `,
        [userId ?? null, sessionId, productId, quantity],
      );
      this.logger.log(
        `[CART] Added new product [${product.name}] (qty: ${quantity}) to cart`,
      );
    }

    return this.getCart(sessionId, userId);
  }

  /**
   * Cập nhật số lượng của một mục trong giỏ hàng
   */
  updateItemQuantity(
    itemId: number,
    quantity: number,
    sessionId: string = 'demo-guest-session-pbl4',
    userId?: number,
  ): CartSummary {
    const item = this.findCartItem(itemId, sessionId, userId);
    if (!item) {
      throw new NotFoundException(
        `Không tìm thấy mục giỏ hàng có ID [${itemId}]`,
      );
    }

    if (quantity <= 0) {
      // Số lượng <= 0 tương đương xóa khỏi giỏ
      return this.removeItem(itemId, sessionId, userId);
    }

    this.db.query('UPDATE cart_items SET quantity = ? WHERE id = ?', [
      quantity,
      itemId,
    ]);
    return this.getCart(sessionId, userId);
  }

  /**
   * Xóa một mục khỏi giỏ hàng
   */
  removeItem(
    itemId: number,
    sessionId: string = 'demo-guest-session-pbl4',
    userId?: number,
  ): CartSummary {
    const item = this.findCartItem(itemId, sessionId, userId);
    if (!item) {
      throw new NotFoundException(
        `Không tìm thấy mục giỏ hàng có ID [${itemId}]`,
      );
    }

    this.db.query('DELETE FROM cart_items WHERE id = ?', [itemId]);
    this.logger.log(`[CART] Removed cart item [${itemId}]`);
    return this.getCart(sessionId, userId);
  }

  /**
   * Xóa sạch toàn bộ giỏ hàng của session
   */
  clearCart(
    sessionId: string = 'demo-guest-session-pbl4',
    userId?: number,
  ): { status: string; message: string } {
    this.db.query(
      `
      DELETE FROM cart_items 
      WHERE session_id = ? OR (user_id IS NOT NULL AND user_id = ?)
    `,
      [sessionId, userId ?? -1],
    );
    this.logger.log(`[CART] Cleared cart for session [${sessionId}]`);
    return {
      status: 'success',
      message: 'Đã xóa toàn bộ giỏ hàng',
    };
  }

  private findCartItem(itemId: number, sessionId: string, userId?: number) {
    const rows = this.db.query(
      `
      SELECT id FROM cart_items 
      WHERE id = ? AND (session_id = ? OR (user_id IS NOT NULL AND user_id = ?))
    `,
      [itemId, sessionId, userId ?? -1],
    );
    return rows && rows.length > 0 ? rows[0] : null;
  }
}
