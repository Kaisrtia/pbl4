/**
 * Ring Buffer (Bộ đệm vòng FIFO cố định dung lượng trong RAM)
 * Lưu trữ tối đa N bản tin TelemetryLog gần nhất.
 * Khi đầy, bản tin cũ nhất sẽ bị tự động loại bỏ để nhường chỗ cho bản tin mới.
 */
export class RingBuffer<T> {
  private buffer: T[];
  private capacity: number;

  constructor(capacity: number = 300) {
    this.capacity = capacity;
    this.buffer = [];
  }

  /**
   * Đẩy một phần tử mới vào bộ đệm FIFO
   */
  public push(item: T): void {
    this.buffer.push(item);
    if (this.buffer.length > this.capacity) {
      this.buffer.shift(); // Loại bỏ phần tử cũ nhất ở đầu mảng
    }
  }

  /**
   * Lấy toàn bộ danh sách bản tin hiện có trong bộ đệm (theo thứ tự thời gian)
   */
  public getAll(): T[] {
    return [...this.buffer];
  }

  /**
   * Lấy danh sách bản tin mới nhất xếp trước (cho table logs)
   */
  public getRecentFirst(): T[] {
    return [...this.buffer].reverse();
  }

  /**
   * Xóa rỗng toàn bộ bộ đệm
   */
  public clear(): void {
    this.buffer = [];
  }

  /**
   * Số lượng phần tử hiện có trong bộ đệm
   */
  public size(): number {
    return this.buffer.length;
  }

  /**
   * Dung lượng tối đa
   */
  public getCapacity(): number {
    return this.capacity;
  }
}
