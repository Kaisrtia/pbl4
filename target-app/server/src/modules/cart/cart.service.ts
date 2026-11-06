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

  /**
   * Thanh toán giỏ hàng (Chỉ dành cho người dùng đã xác thực JWT)
   */
  checkout(
    userId: number,
    sessionId: string = 'demo-guest-session-pbl4',
    shippingAddress: string = 'Hà Nội, Việt Nam',
  ) {
    // Match the session-scoped cart displayed by GET /cart. JWT identifies
    // the order owner; it must not pull unseen items from other sessions.
    const cart = this.getCart(sessionId);
    if (!cart.items || cart.items.length === 0) {
      throw new BadRequestException(
        'Giỏ hàng của bạn đang trống! Vui lòng chọn linh kiện trước khi thanh toán.',
      );
    }

    // 2. Tạo mã hóa đơn điện tử duy nhất
    const orderCode = `ORD-${Date.now().toString(36).toUpperCase()}-${Math.floor(1000 + Math.random() * 9000)}`;

    // 3. Khởi tạo đơn hàng trong cơ sở dữ liệu
    this.db.query(
      `
      INSERT INTO orders (order_code, user_id, total_amount, total_items, shipping_address, status)
      VALUES (?, ?, ?, ?, ?, 'COMPLETED')
    `,
      [orderCode, userId, cart.total_price, cart.total_items, shippingAddress],
    );

    const createdOrderRows = this.db.query(
      'SELECT id, order_code, user_id, total_amount, total_items, shipping_address, status, created_at FROM orders WHERE order_code = ?',
      [orderCode],
    );
    const order = createdOrderRows[0];

    // 4. Lưu từng mục sản phẩm vào bảng order_items
    for (const item of cart.items) {
      this.db.query(
        `
        INSERT INTO order_items (order_id, product_id, product_name, product_sku, price, quantity, subtotal)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
        [
          order.id,
          item.product_id,
          item.name,
          item.sku,
          item.price,
          item.quantity,
          item.subtotal,
        ],
      );
    }

    // 5. Xóa sạch giỏ hàng sau khi hoàn tất thủ tục thanh toán
    this.clearCart(sessionId);

    this.logger.log(
      `[CHECKOUT] User ID [${userId}] placed order [${orderCode}] (${cart.total_items} items, ${cart.total_price.toLocaleString('vi-VN')} VND)`,
    );

    return {
      status: 'success',
      message: `🎉 Đặt hàng thành công! Đơn hàng #${orderCode} đã được tạo và thanh toán hoàn tất.`,
      order: {
        id: order.id,
        order_code: order.order_code,
        user_id: order.user_id,
        total_amount: order.total_amount,
        total_items: order.total_items,
        shipping_address: order.shipping_address,
        status: order.status,
        created_at: order.created_at,
        items: cart.items,
      },
    };
  }

  /**
   * Lấy lịch sử danh sách đơn hàng đã đặt của người dùng
   */
  getOrders(userId: number) {
    const orders = this.db.query(
      `
      SELECT id, order_code, user_id, total_amount, total_items, shipping_address, status, created_at
      FROM orders
      WHERE user_id = ?
      ORDER BY id DESC
    `,
      [userId],
    );

    return orders.map((order: any) => {
      const items = this.db.query(
        `
        SELECT id, product_id, product_name, product_sku, price, quantity, subtotal
        FROM order_items
        WHERE order_id = ?
        ORDER BY id ASC
      `,
        [order.id],
      );
      return {
        ...order,
        items,
      };
    });
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
