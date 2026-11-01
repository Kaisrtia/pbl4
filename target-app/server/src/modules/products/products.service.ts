import { Injectable, NotFoundException } from '@nestjs/common';
import { DatabaseService } from '../../database/database.service';
import type { ProductItem } from '@shared/schemas/shop-api';

export type { ProductItem };

@Injectable()
export class ProductsService {
  constructor(private readonly db: DatabaseService) {}

  /**
   * Lấy danh sách danh mục kèm số lượng sản phẩm thực tế (phục vụ Filter Pills: Tất cả, Vi điều khiển (2)...)
   */
  getCategoriesWithCount() {
    const categories = this.db.query(`
      SELECT 
        c.id, 
        c.slug, 
        c.name, 
        c.description, 
        c.display_order,
        COUNT(p.id) as product_count
      FROM categories c
      LEFT JOIN products p ON c.id = p.category_id
      GROUP BY c.id
      ORDER BY c.display_order ASC
    `);

    const totalCount =
      this.db.query('SELECT COUNT(*) as total FROM products')[0]?.total || 0;

    return {
      total_products: totalCount,
      categories: categories.map((cat: any) => ({
        id: cat.id,
        slug: cat.slug,
        name: cat.name,
        description: cat.description,
        count: cat.product_count,
      })),
    };
  }

  /**
   * Lấy danh sách sản phẩm có hỗ trợ lọc theo Danh mục, Tìm kiếm và Sắp xếp
   */
  getProducts(params?: {
    category?: string;
    search?: string;
    sort?: string;
  }): ProductItem[] {
    let sql = `
      SELECT 
        p.*,
        c.name as category_name,
        c.slug as category_slug
      FROM products p
      JOIN categories c ON p.category_id = c.id
      WHERE 1=1
    `;
    const queryParams: any[] = [];

    // 1. Lọc theo danh mục slug (vi-dieu-khien, cam-bien, module-nguon)
    if (params?.category && params.category !== 'all') {
      sql += ' AND c.slug = ?';
      queryParams.push(params.category);
    }

    // 2. Tìm kiếm theo tên, mã SKU, hãng sản xuất hoặc mô tả
    if (params?.search && params.search.trim() !== '') {
      sql +=
        ' AND (p.name LIKE ? OR p.sku LIKE ? OR p.brand LIKE ? OR p.description LIKE ?)';
      const keyword = `%${params.search.trim()}%`;
      queryParams.push(keyword, keyword, keyword, keyword);
    }

    // 3. Sắp xếp
    if (params?.sort === 'price_asc') {
      sql += ' ORDER BY p.price ASC';
    } else if (params?.sort === 'price_desc') {
      sql += ' ORDER BY p.price DESC';
    } else {
      sql += ' ORDER BY p.id ASC';
    }

    const rows = this.db.query(sql, queryParams);
    return rows.map((row: any) => this.formatProduct(row));
  }

  /**
   * Xem chi tiết một sản phẩm theo ID
   */
  getProductById(id: number): ProductItem {
    const rows = this.db.query(
      `
      SELECT 
        p.*,
        c.name as category_name,
        c.slug as category_slug
      FROM products p
      JOIN categories c ON p.category_id = c.id
      WHERE p.id = ?
    `,
      [id],
    );

    if (!rows || rows.length === 0) {
      throw new NotFoundException(`Không tìm thấy sản phẩm có ID [${id}]`);
    }

    return this.formatProduct(rows[0]);
  }

  /**
   * Xem chi tiết một sản phẩm theo mã SKU (vd: MCU-ARD-R4)
   */
  getProductBySku(sku: string): ProductItem {
    const rows = this.db.query(
      `
      SELECT 
        p.*,
        c.name as category_name,
        c.slug as category_slug
      FROM products p
      JOIN categories c ON p.category_id = c.id
      WHERE p.sku = ?
    `,
      [sku],
    );

    if (!rows || rows.length === 0) {
      throw new NotFoundException(`Không tìm thấy sản phẩm có mã SKU [${sku}]`);
    }

    return this.formatProduct(rows[0]);
  }

  /**
   * Format dữ liệu và parse trường specs_json thành mảng JavaScript
   */
  private formatProduct(row: any): ProductItem {
    let specs: string[] = [];
    if (row.specs_json) {
      try {
        specs = JSON.parse(row.specs_json);
      } catch {
        specs = [];
      }
    }

    return {
      id: row.id,
      category_id: row.category_id,
      category_name: row.category_name,
      category_slug: row.category_slug,
      sku: row.sku,
      name: row.name,
      brand: row.brand,
      description: row.description,
      price: row.price,
      stock: row.stock,
      image_url: row.image_url,
      specs,
      created_at: row.created_at,
    };
  }
}
