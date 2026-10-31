import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  Headers,
  Req,
  ParseIntPipe,
} from '@nestjs/common';
import { CartService } from './cart.service';
import { AddToCartDto } from './dto/add-to-cart.dto';
import { UpdateCartItemDto } from './dto/update-cart-item.dto';

@Controller('cart')
export class CartController {
  constructor(private readonly cartService: CartService) {}

  private resolveSession(
    headerSession?: string,
    querySession?: string,
  ): string {
    return querySession || headerSession || 'demo-guest-session-pbl4';
  }

  /**
   * 1. GET /api/cart
   * Lấy danh sách sản phẩm trong giỏ hàng & tổng số lượng (Badge Navbar)
   */
  @Get()
  getCart(
    @Headers('x-session-id') headerSession?: string,
    @Query('session_id') querySession?: string,
    @Req() req?: any,
  ) {
    const sessionId = this.resolveSession(headerSession, querySession);
    const userId = req?.user?.sub;
    const cart = this.cartService.getCart(sessionId, userId);
    return {
      status: 'success',
      data: cart,
    };
  }

  /**
   * 2. POST /api/cart
   * Thêm sản phẩm vào giỏ hàng khi người dùng bấm "Thêm giỏ"
   */
  @Post()
  addToCart(
    @Body() dto: AddToCartDto,
    @Headers('x-session-id') headerSession?: string,
    @Query('session_id') querySession?: string,
    @Req() req?: any,
  ) {
    const sessionId = this.resolveSession(headerSession, querySession);
    const userId = req?.user?.sub;
    const cart = this.cartService.addItem(
      dto.productId,
      dto.quantity ?? 1,
      sessionId,
      userId,
    );
    return {
      status: 'success',
      message: 'Đã thêm sản phẩm vào giỏ hàng',
      data: cart,
    };
  }

  /**
   * 3. PATCH /api/cart/items/:id
   * Cập nhật số lượng của một mục sản phẩm trong giỏ
   */
  @Patch('items/:id')
  updateQuantity(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateCartItemDto,
    @Headers('x-session-id') headerSession?: string,
    @Query('session_id') querySession?: string,
    @Req() req?: any,
  ) {
    const sessionId = this.resolveSession(headerSession, querySession);
    const userId = req?.user?.sub;
    const cart = this.cartService.updateItemQuantity(
      id,
      dto.quantity,
      sessionId,
      userId,
    );
    return {
      status: 'success',
      message: 'Đã cập nhật số lượng',
      data: cart,
    };
  }

  /**
   * 4. DELETE /api/cart/items/:id
   * Xóa một sản phẩm khỏi giỏ hàng
   */
  @Delete('items/:id')
  removeItem(
    @Param('id', ParseIntPipe) id: number,
    @Headers('x-session-id') headerSession?: string,
    @Query('session_id') querySession?: string,
    @Req() req?: any,
  ) {
    const sessionId = this.resolveSession(headerSession, querySession);
    const userId = req?.user?.sub;
    const cart = this.cartService.removeItem(id, sessionId, userId);
    return {
      status: 'success',
      message: 'Đã xóa sản phẩm khỏi giỏ hàng',
      data: cart,
    };
  }

  /**
   * 5. DELETE /api/cart
   * Xóa toàn bộ giỏ hàng
   */
  @Delete()
  clearCart(
    @Headers('x-session-id') headerSession?: string,
    @Query('session_id') querySession?: string,
    @Req() req?: any,
  ) {
    const sessionId = this.resolveSession(headerSession, querySession);
    const userId = req?.user?.sub;
    const result = this.cartService.clearCart(sessionId, userId);
    return result;
  }
}
