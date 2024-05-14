import { JwtPayload } from '@auth/types';
import { convertToSecondsUtil } from '@common/utils';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Role, Token, User } from '@prisma/client';
import { PrismaService } from '@prisma/prisma.service';
import { genSaltSync, hashSync } from 'bcrypt';
import { Cache } from 'cache-manager';

@Injectable()
export class UserService {
  constructor(
    private readonly prismaService: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly configService: ConfigService,
  ) {}

  async create(userData: Partial<User>) {
    const hashedPassword = userData?.password ? this.hashPassword(userData.password) : null;
    const savedUser = await this.prismaService.user.upsert({
      where: {
        email: userData.email,
      },
      update: {
        password: hashedPassword,
        provider: userData?.provider,
        roles: userData.roles,
      },
      create: {
        email: userData.email,
        password: hashedPassword,
        roles: ['USER'],
        provider: userData?.provider,
      },
    });
    await this.cacheManager.set(savedUser.id, savedUser);
    await this.cacheManager.set(savedUser.email, savedUser);
    return savedUser;
  }

  async findOne(idOrEmail: string, isReset = false) {
    if (isReset) {
      await this.cacheManager.del(idOrEmail);
    }
    const user = await this.cacheManager.get<User>(idOrEmail);
    if (!user) {
      const user = await this.prismaService.user.findFirst({
        where: {
          OR: [{ id: idOrEmail }, { email: idOrEmail }],
        },
      });
      if (!user) {
        return null;
      }
      await this.cacheManager.set(idOrEmail, user, convertToSecondsUtil(this.configService.get('JWT_EXP')));
      return user;
    }
    return user;
  }

  async delete(id: string, user: JwtPayload) {
    if (user.id !== id && !user.roles.includes(Role.ADMIN)) {
      throw new ForbiddenException();
    }
    await Promise.all([this.cacheManager.del(id), this.cacheManager.del(user.email)]);
    return this.prismaService.user.delete({
      where: { id },
      select: {
        id: true,
      },
    });
  }

  update() {}

  private hashPassword(password: string) {
    return hashSync(password, genSaltSync(10));
  }

  async findByToken(refreshToken: string) {
    const token = await this.prismaService.token.findFirst({
      where: {
        token: refreshToken,
      },
    });
    const user = await this.findOne(token.userId);
    return user;
  }
}
