import { Controller, Get, Param, Query, ParseIntPipe } from '@nestjs/common';
import { ProductsService } from './products.service';

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  /**
   * 1. GET /api/products/categories
   * Lấy danh mục kèm số lượng sản phẩm phục vụ các nút lọc (Filter Pills)
   */
  @Get('categories')
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
  getProductById(@Param('id', ParseIntPipe) id: number) {
    return {
      status: 'success',
      data: this.productsService.getProductById(id),
    };
  }
}
