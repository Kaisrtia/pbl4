import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    example: 'admin',
    description:
      "Tên đăng nhập (Thử payload SQLi: `admin' --` khi Khiên L3 tắt)",
  })
  username!: string;

  @ApiProperty({
    example: 'adminPassword2026!',
    description: 'Mật khẩu tài khoản (Tùy ý nếu khai thác SQLi bypass)',
  })
  password!: string;
}
