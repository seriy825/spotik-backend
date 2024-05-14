import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength } from 'class-validator';
export class GetUserDTO {
  @ApiProperty({ example: '123456789' })
  @IsString()
  token: string;
}
