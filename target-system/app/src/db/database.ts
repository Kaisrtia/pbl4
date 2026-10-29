import fs from 'fs';
import path from 'path';
import { DatabaseSync } from 'node:sqlite';
import { config } from '../config/env';
import { SEED_USERS, SEED_RESOURCES, SeedUser } from './seed-data';
import { User, ResourceItem } from '@shared/schemas';

export interface AuthQueryResult {
  user: User | null;
  executedQuery: string;
  isSqliSuspected: boolean;
  error?: string;
}

export class AppDatabase {
  private db: DatabaseSync;
  private isInitialized = false;

  constructor(dbPath: string = config.dbPath) {
    // Đảm bảo thư mục cha chứa file DB tồn tại
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Khởi tạo kết nối SQLite sử dụng node:sqlite
    this.db = new DatabaseSync(dbPath);
    this.initializeTables();
    this.seedInitialData();
  }

  /**
   * Khởi tạo cấu trúc các bảng users và resources
   */
  private initializeTables(): void {
    // Bảng người dùng
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT NOT NULL DEFAULT 'user',
        fullName TEXT,
        isActive INTEGER NOT NULL DEFAULT 1,
        createdAt TEXT NOT NULL
      );
    `);

    // Bảng tài nguyên mật và sản phẩm
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS resources (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        category TEXT,
        price REAL,
        stock INTEGER,
        fileName TEXT,
        filePath TEXT,
        fileSize INTEGER,
        mimeType TEXT,
        downloadUrl TEXT,
        isPublic INTEGER NOT NULL DEFAULT 0,
        createdBy INTEGER,
        createdAt TEXT NOT NULL,
        metadata TEXT
      );
    `);

    this.isInitialized = true;
  }

  /**
   * Nạp dữ liệu mẫu ban đầu nếu bảng đang rỗng
   */
  public seedInitialData(): void {
    // Kiểm tra và seed người dùng
    const userCountRow = this.db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
    if (userCountRow && userCountRow.count === 0) {
      const insertUser = this.db.prepare(`
        INSERT INTO users (id, username, password, email, role, fullName, isActive, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const u of SEED_USERS) {
        insertUser.run(
          u.id,
          u.username,
          u.password,
          u.email || null,
          u.role,
          u.fullName || null,
          u.isActive ? 1 : 0,
          typeof u.createdAt === 'string' ? u.createdAt : new Date().toISOString()
        );
      }
      console.log(`[Database] Đã khởi tạo thành công ${SEED_USERS.length} tài khoản mẫu.`);
    }

    // Kiểm tra và seed tài nguyên
    const resCountRow = this.db.prepare('SELECT COUNT(*) as count FROM resources').get() as { count: number };
    if (resCountRow && resCountRow.count === 0) {
      const insertResource = this.db.prepare(`
        INSERT INTO resources (
          id, name, description, category, price, stock,
          fileName, filePath, fileSize, mimeType, downloadUrl,
          isPublic, createdBy, createdAt, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const r of SEED_RESOURCES) {
        insertResource.run(
          String(r.id),
          r.name,
          r.description || null,
          r.category || null,
          r.price || null,
          r.stock || null,
          r.fileName || null,
          r.filePath || null,
          r.fileSize || null,
          r.mimeType || null,
          r.downloadUrl || null,
          r.isPublic ? 1 : 0,
          r.createdBy ? Number(r.createdBy) : null,
          typeof r.createdAt === 'string' ? r.createdAt : new Date().toISOString(),
          r.metadata ? JSON.stringify(r.metadata) : null
        );
      }
      console.log(`[Database] Đã khởi tạo thành công ${SEED_RESOURCES.length} tài nguyên mẫu.`);
    }
  }

  /**
   * Tìm kiếm user theo thông tin đăng nhập
   * Hỗ trợ 2 chế độ:
   * 1. allowSqli = true (Mặc định khi L3 defense tắt): Nối chuỗi SQL raw -> Dễ bị khai thác SQL Injection
   * 2. allowSqli = false (Khi L3 defense bật): Dùng Parameterized Query an toàn tuyệt đối
   */
  public findUserByCredentials(username: string, password: string, allowSqli: boolean = false): AuthQueryResult {
    // Phát hiện ký tự nghi vấn SQLi sơ bộ
    const sqliPatterns = /('|--|#|\/\*|\*\/|union\s+select|or\s+['\d\w]+\s*=\s*['\d\w]+)/i;
    const isSqliSuspected = sqliPatterns.test(username) || sqliPatterns.test(password);

    if (allowSqli) {
      // CHẾ ĐỘ CÓ LỖ HỔNG (Vulnerable SQL Injection)
      // Nối chuỗi trực tiếp: Cho phép attacker bypass bằng payload: admin' -- hoặc ' OR '1'='1
      const rawSql = `SELECT id, username, email, role, fullName, isActive, createdAt FROM users WHERE username = '${username}' AND password = '${password}'`;
      try {
        const rows = this.db.prepare(rawSql).all() as any[];
        if (rows && rows.length > 0) {
          const u = rows[0];
          return {
            user: {
              id: u.id,
              username: u.username,
              email: u.email,
              role: u.role,
              fullName: u.fullName,
              isActive: Boolean(u.isActive),
              createdAt: u.createdAt,
            },
            executedQuery: rawSql,
            isSqliSuspected,
          };
        }
        return { user: null, executedQuery: rawSql, isSqliSuspected };
      } catch (err: any) {
        return {
          user: null,
          executedQuery: rawSql,
          isSqliSuspected: true,
          error: err.message,
        };
      }
    } else {
      // CHẾ ĐỘ PHÒNG THỦ AN TOÀN (Parameterized Query)
      const safeSql = `SELECT id, username, email, role, fullName, isActive, createdAt FROM users WHERE username = ? AND password = ?`;
      try {
        const row = this.db.prepare(safeSql).get(username, password) as any;
        if (row) {
          return {
            user: {
              id: row.id,
              username: row.username,
              email: row.email,
              role: row.role,
              fullName: row.fullName,
              isActive: Boolean(row.isActive),
              createdAt: row.createdAt,
            },
            executedQuery: safeSql,
            isSqliSuspected,
          };
        }
        return { user: null, executedQuery: safeSql, isSqliSuspected };
      } catch (err: any) {
        return {
          user: null,
          executedQuery: safeSql,
          isSqliSuspected,
          error: err.message,
        };
      }
    }
  }

  /**
   * Tìm người dùng theo ID
   */
  public findUserById(id: string | number): User | null {
    const row = this.db.prepare('SELECT id, username, email, role, fullName, isActive, createdAt FROM users WHERE id = ?').get(id) as any;
    if (!row) return null;
    return {
      id: row.id,
      username: row.username,
      email: row.email,
      role: row.role,
      fullName: row.fullName,
      isActive: Boolean(row.isActive),
      createdAt: row.createdAt,
    };
  }

  /**
   * Lấy danh sách tài nguyên (hỗ trợ lọc tài nguyên công khai hoặc mật)
   */
  public getAllResources(options?: { isPublicOnly?: boolean; category?: string }): ResourceItem[] {
    let query = 'SELECT * FROM resources WHERE 1=1';
    const params: any[] = [];

    if (options?.isPublicOnly) {
      query += ' AND isPublic = 1';
    }

    if (options?.category) {
      query += ' AND category = ?';
      params.push(options.category);
    }

    query += ' ORDER BY createdAt DESC';

    const rows = this.db.prepare(query).all(...params) as any[];
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      category: r.category,
      price: r.price,
      stock: r.stock,
      fileName: r.fileName,
      filePath: r.filePath,
      fileSize: r.fileSize,
      mimeType: r.mimeType,
      downloadUrl: r.downloadUrl,
      isPublic: Boolean(r.isPublic),
      createdBy: r.createdBy,
      createdAt: r.createdAt,
      metadata: r.metadata ? JSON.parse(r.metadata) : undefined,
    }));
  }

  /**
   * Lấy chi tiết 1 tài nguyên theo ID
   */
  public getResourceById(id: string | number): ResourceItem | null {
    const row = this.db.prepare('SELECT * FROM resources WHERE id = ?').get(String(id)) as any;
    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      category: row.category,
      price: row.price,
      stock: row.stock,
      fileName: row.fileName,
      filePath: row.filePath,
      fileSize: row.fileSize,
      mimeType: row.mimeType,
      downloadUrl: row.downloadUrl,
      isPublic: Boolean(row.isPublic),
      createdBy: row.createdBy,
      createdAt: row.createdAt,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
    };
  }

  /**
   * Xóa và tái khởi tạo lại dữ liệu (dành cho script reset lab)
   */
  public resetDatabase(): void {
    this.db.exec('DROP TABLE IF EXISTS users');
    this.db.exec('DROP TABLE IF EXISTS resources');
    this.initializeTables();
    this.seedInitialData();
  }
}

// Khởi tạo singleton instance cho toàn bộ ứng dụng
export const db = new AppDatabase();
