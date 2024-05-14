import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Put,
  UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UserResponse } from './responses';
import { Cookie, CurrentUser } from '@common/decorators';
import { JwtPayload } from '@auth/types';
import { User } from '@prisma/client';
import { REFRESH_TOKEN } from 'src/utils/constants';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @UseInterceptors(ClassSerializerInterceptor)
  @Get('current')
  async getCurrentUser(@Cookie(REFRESH_TOKEN) refreshToken: string) {
    const user = await this.userService.findByToken(refreshToken);
    return new UserResponse(user);
  }

  @UseInterceptors(ClassSerializerInterceptor)
  @Get(':idOrEmail')
  async findOneUser(@Param('idOrEmail') idOrEmail: string) {
    const user = await this.userService.findOne(idOrEmail);
    return new UserResponse(user);
  }

  @Delete(':id')
  deleteUser(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() user: JwtPayload) {
    return this.userService.delete(id, user);
  }

  @UseInterceptors(ClassSerializerInterceptor)
  @Put()
  async updateUser(@Body() body: Partial<User>) {
    const user = await this.userService.create(body);
    return new UserResponse(user);
  }
}
