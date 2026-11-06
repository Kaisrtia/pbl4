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
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiHeader,
  ApiQuery,
  ApiParam,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { CartService } from './cart.service';
import { AddToCartDto } from './dto/add-to-cart.dto';
import { UpdateCartItemDto } from './dto/update-cart-item.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('Cart')
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
  @ApiOperation({
    summary: 'Lấy thông tin giỏ hàng & số lượng cho badge Navbar',
    description:
      'Mặc định dùng session khách demo `demo-guest-session-pbl4` (trả về sẵn 2 món linh kiện khớp badge [2] trên UI).',
  })
  @ApiHeader({
    name: 'x-session-id',
    required: false,
    description: 'ID phiên khách (Session ID)',
  })
  @ApiQuery({
    name: 'session_id',
    required: false,
    description: 'Hoặc truyền qua query param',
  })
  @ApiResponse({ status: 200, description: 'Lấy giỏ hàng thành công' })
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
  @ApiOperation({
    summary: 'Thêm linh kiện vào giỏ hàng',
    description: 'Bấm nút "Thêm giỏ" trên thẻ sản phẩm để thêm vào giỏ.',
  })
  @ApiHeader({ name: 'x-session-id', required: false })
  @ApiResponse({ status: 201, description: 'Đã thêm sản phẩm vào giỏ hàng' })
  @ApiResponse({ status: 404, description: 'Không tìm thấy sản phẩm' })
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
  @ApiOperation({ summary: 'Cập nhật số lượng linh kiện trong giỏ' })
  @ApiParam({ name: 'id', example: 1, description: 'ID của mục trong giỏ' })
  @ApiHeader({ name: 'x-session-id', required: false })
  @ApiResponse({ status: 200, description: 'Đã cập nhật số lượng' })
  @ApiResponse({ status: 404, description: 'Không tìm thấy mục giỏ hàng' })
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
  @ApiOperation({ summary: 'Xóa một linh kiện khỏi giỏ' })
  @ApiParam({ name: 'id', example: 1, description: 'ID của mục trong giỏ' })
  @ApiHeader({ name: 'x-session-id', required: false })
  @ApiResponse({ status: 200, description: 'Đã xóa sản phẩm khỏi giỏ hàng' })
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
  @ApiOperation({ summary: 'Xóa toàn bộ sản phẩm trong giỏ hàng' })
  @ApiHeader({ name: 'x-session-id', required: false })
  @ApiResponse({ status: 200, description: 'Đã xóa toàn bộ giỏ hàng' })
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

  /**
   * 6. POST /api/cart/checkout
   * Thanh toán giỏ hàng (BẮT BUỘC ĐĂNG NHẬP - BẢO VỆ BỞI JWT GUARD)
   */
  @Post('checkout')
  @HttpCode(HttpStatus.CREATED)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary:
      'Thanh toán đơn hàng & Chuyển đổi giỏ hàng thành Order (Bắt buộc JWT)',
    description:
      'Chỉ người dùng đã đăng nhập có Token JWT hợp lệ mới được thực hiện thanh toán. Trả về mã 401 Unauthorized nếu chưa đăng nhập.',
  })
  @ApiHeader({ name: 'x-session-id', required: false })
  @ApiResponse({
    status: 201,
    description: 'Thanh toán thành công, trả về mã đơn hàng và chi tiết đơn.',
  })
  @ApiResponse({
    status: 401,
    description:
      'Chưa đăng nhập - Vui lòng gửi Header Authorization: Bearer <token>.',
  })
  @ApiResponse({
    status: 400,
    description: 'Giỏ hàng đang trống, không thể thanh toán.',
  })
  checkout(
    @Req() req: any,
    @Headers('x-session-id') headerSession?: string,
    @Query('session_id') querySession?: string,
    @Body() body?: { shippingAddress?: string },
  ) {
    const sessionId = this.resolveSession(headerSession, querySession);
    const userId = req.user.sub;
    const shippingAddress = body?.shippingAddress || 'Hà Nội, Việt Nam';
    return this.cartService.checkout(userId, sessionId, shippingAddress);
  }

  /**
   * 7. GET /api/cart/orders
   * Lấy lịch sử đơn hàng của người dùng hiện tại (BẮT BUỘC ĐĂNG NHẬP - BẢO VỆ BỞI JWT GUARD)
   */
  @Get('orders')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary:
      'Lấy danh sách lịch sử đơn hàng của tài khoản đang đăng nhập (Bắt buộc JWT)',
  })
  @ApiResponse({
    status: 200,
    description: 'Lấy lịch sử đơn hàng thành công.',
  })
  @ApiResponse({
    status: 401,
    description: 'Chưa đăng nhập hoặc Token JWT không hợp lệ.',
  })
  getOrders(@Req() req: any) {
    const userId = req.user.sub;
    const orders = this.cartService.getOrders(userId);
    return {
      status: 'success',
      total: orders.length,
      data: orders,
    };
  }
}
