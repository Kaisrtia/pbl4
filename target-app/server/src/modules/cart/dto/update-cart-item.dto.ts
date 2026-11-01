import { ApiProperty } from '@nestjs/swagger';

export class UpdateCartItemDto {
  @ApiProperty({
    example: 2,
    description: 'Số lượng mới cho mục giỏ hàng (<= 0 sẽ xóa món khỏi giỏ)',
  })
  quantity!: number;
}
