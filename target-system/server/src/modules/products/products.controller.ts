import { Controller, Get, Param, Query, ParseIntPipe } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiQuery,
  ApiParam,
  ApiResponse,
} from '@nestjs/swagger';
import { ProductsService } from './products.service';

@ApiTags('Products')
@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  /**
   * 1. GET /api/products/categories
   * Lấy danh mục kèm số lượng sản phẩm phục vụ các nút lọc (Filter Pills)
   */
  @Get('categories')
  @ApiOperation({
    summary: 'Lấy danh sách danh mục & số lượng linh kiện',
    description:
      'Dùng để hiển thị các Filter Pills: Tất cả (6), Vi điều khiển (2), Cảm biến (2), Module nguồn (2).',
  })
  @ApiResponse({ status: 200, description: 'Lấy danh mục thành công' })
  getCategories() {
    return {
      status: 'success',
      data: this.productsService.getCategoriesWithCount(),
    };
  }

  /**
   * 2. GET /api/products
   * Lấy danh sách linh kiện điện tử (Hỗ trợ lọc theo category, tìm kiếm search, và sort)
   */
  @Get()
  @ApiOperation({
    summary: 'Lấy danh sách linh kiện ElectroShop',
    description:
      'Hỗ trợ lọc theo category slug (vi-dieu-khien, cam-bien, module-nguon), tìm kiếm từ khóa, và sắp xếp theo giá.',
  })
  @ApiQuery({
    name: 'category',
    required: false,
    description: 'Slug danh mục cần lọc (ví dụ: vi-dieu-khien)',
  })
  @ApiQuery({
    name: 'search',
    required: false,
    description: 'Từ khóa tìm kiếm theo tên, SKU, hãng sx',
  })
  @ApiQuery({
    name: 'sort',
    required: false,
    enum: ['price_asc', 'price_desc'],
    description: 'Kiểu sắp xếp theo giá',
  })
  @ApiResponse({
    status: 200,
    description: 'Lấy danh sách linh kiện thành công',
  })
  getProducts(
    @Query('category') category?: string,
    @Query('search') search?: string,
    @Query('sort') sort?: string,
  ) {
    const products = this.productsService.getProducts({
      category,
      search,
      sort,
    });
    return {
      status: 'success',
      total: products.length,
      data: products,
    };
  }

  /**
   * 3. GET /api/products/sku/:sku
   * Xem chi tiết sản phẩm theo mã SKU (ví dụ: MCU-ARD-R4)
   */
  @Get('sku/:sku')
  @ApiOperation({ summary: 'Xem chi tiết sản phẩm theo mã linh kiện (SKU)' })
  @ApiParam({
    name: 'sku',
    example: 'MCU-ARD-R4',
    description: 'Mã linh kiện SKU',
  })
  @ApiResponse({ status: 200, description: 'Tìm thấy sản phẩm' })
  @ApiResponse({ status: 404, description: 'Không tìm thấy sản phẩm' })
  getProductBySku(@Param('sku') sku: string) {
    return {
      status: 'success',
      data: this.productsService.getProductBySku(sku),
    };
  }

  /**
   * 4. GET /api/products/:id
   * Xem chi tiết sản phẩm theo ID số
   */
  @Get(':id')
  @ApiOperation({ summary: 'Xem chi tiết sản phẩm theo ID' })
  @ApiParam({ name: 'id', example: 1, description: 'ID số của sản phẩm' })
  @ApiResponse({ status: 200, description: 'Tìm thấy sản phẩm' })
  @ApiResponse({ status: 404, description: 'Không tìm thấy sản phẩm' })
  getProductById(@Param('id', ParseIntPipe) id: number) {
    return {
      status: 'success',
      data: this.productsService.getProductById(id),
    };
  }
}
