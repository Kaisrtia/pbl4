import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AddToCartDto {
  @ApiProperty({ example: 1, description: 'ID của sản phẩm cần thêm vào giỏ' })
  productId!: number;

  @ApiPropertyOptional({
    example: 1,
    default: 1,
    description: 'Số lượng sản phẩm muốn thêm',
  })
  quantity?: number;
}
