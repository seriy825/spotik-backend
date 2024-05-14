import { IsPasswordConfirmed } from '@common/decorators';
import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength, Validate } from 'class-validator';

export class SignUpDTO {
  @ApiProperty({ example: 'Serhii Olar' })
  @IsString()
  name: string;

  @ApiProperty({ example: 'serezhaolar@gmail.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: '123456' })
  @IsString()
  @MinLength(8)
  @Validate(IsPasswordConfirmed)
  password: string;

  @ApiProperty({ example: '123456' })
  @ApiProperty()
  @IsString()
  @MinLength(8)
  passwordConfirmation: string;
}
