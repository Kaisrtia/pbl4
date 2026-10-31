/**
 * ==============================================================================
 * Project: PBL4 - ElectroShop Shared API Contracts & Types
 * Target Systems: Backend NestJS (target-app/server) & Frontend Next.js (target-app/client)
 * ==============================================================================
 */

// ------------------------------------------------------------------------------
// 1. DANH MỤC & SẢN PHẨM (CATEGORIES & PRODUCTS)
// ------------------------------------------------------------------------------

export interface CategoryItem {
  id: number;
  slug: string;
  name: string;
  description?: string;
  count?: number;
}

export interface CategoriesSummaryResponse {
  total_products: number;
  categories: CategoryItem[];
}

export interface ProductItem {
  id: number;
  category_id: number;
  category_name?: string;
  category_slug?: string;
  sku: string;
  name: string;
  brand: string;
  description: string;
  price: number;
  stock: number;
  image_url: string;
  specs: string[];
  created_at: string;
}

export interface ProductFilterQuery {
  category?: string;
  search?: string;
  sort?: 'price_asc' | 'price_desc' | string;
}

// ------------------------------------------------------------------------------
// 2. GIỎ HÀNG (SHOPPING CART)
// ------------------------------------------------------------------------------

export interface CartProductItem {
  id: number;
  product_id: number;
  sku: string;
  name: string;
  brand: string;
  price: number;
  stock: number;
  image_url: string;
  quantity: number;
  subtotal: number;
}

export interface CartSummary {
  total_items: number;
  total_price: number;
  items: CartProductItem[];
}

export interface AddToCartRequest {
  productId: number;
  quantity?: number;
}

export interface UpdateCartItemRequest {
  quantity: number;
}

// ------------------------------------------------------------------------------
// 3. TÀI LIỆU KỸ THUẬT (TECHNICAL DOCUMENTS)
// ------------------------------------------------------------------------------

export interface DocumentItem {
  id: number;
  product_id: number | null;
  product_name?: string;
  product_sku?: string;
  title: string;
  file_name: string;
  file_size_kb: number;
  is_confidential: boolean;
  download_url: string;
  created_at: string;
}

export interface DocumentFilterQuery {
  search?: string;
  productId?: number;
  includeConfidential?: boolean;
}

// ------------------------------------------------------------------------------
// 4. XÁC THỰC & NGƯỜI DÙNG (AUTHENTICATION & USER)
// ------------------------------------------------------------------------------

export interface AuthUser {
  id: number;
  username: string;
  role: string;
  fullName?: string;
  email?: string;
}

export interface LoginResponse {
  status: 'success' | 'error';
  message: string;
  user: AuthUser;
  defense_mode: 'SECURED_PREPARED_QUERY' | 'VULNERABLE_RAW_SQL';
  sqli_bypassed: boolean;
  token_type: 'Bearer';
  access_token: string;
  token: string;
  expires_in: string;
}

// ------------------------------------------------------------------------------
// 5. TRẠNG THÁI PHÒNG THỦ KHIÊN L3 (LAB DEFENSE STATUS)
// ------------------------------------------------------------------------------

export interface DefenseStatus {
  l3_master: boolean;
  anti_sqli: boolean;
  rate_limit: boolean;
  input_sanitization: boolean;
}
