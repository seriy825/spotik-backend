import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { SignInDTO, SignUpDTO } from './dto';
import { UserService } from '@user/user.service';
import { Tokens, UserWithTokens } from './types';
import { compareSync } from 'bcrypt';
import { Provider, Token, User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '@prisma/prisma.service';
import { v4 } from 'uuid';
import { add } from 'date-fns';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
  ) {}

  async signUp(signUpDTO: SignUpDTO) {
    const user: User = await this.userService.findOne(signUpDTO.email).catch((err) => {
      this.logger.error(err);
      return null;
    });
    if (user) {
      throw new HttpException('User with same e-mail already exists!', HttpStatus.CONFLICT);
    }
    return this.userService.create(signUpDTO).catch((err) => {
      this.logger.error(err);
      throw err;
    });
  }

  async signIn({ email, password }: SignInDTO, agent: string): Promise<UserWithTokens> {
    const user: User = await this.userService.findOne(email, true).catch((err) => {
      this.logger.error(err);
      return null;
    });
    if (!user || compareSync(password, user.password)) {
      throw new HttpException('User with this credentials is not found in system.', HttpStatus.UNAUTHORIZED);
    }
    const tokens = await this.generateTokens(user, agent);
    return {
      user,
      tokens,
    };
  }

  async refreshTokens(refreshToken: string, agent: string): Promise<UserWithTokens> {
    const token = await this.prismaService.token.delete({
      where: {
        token: refreshToken,
      },
    });
    if (!token || new Date(token.exp) < new Date()) {
      throw new HttpException('Unauthorized action!', HttpStatus.UNAUTHORIZED);
    }
    const user = await this.userService.findOne(token.userId);
    const tokens = await this.generateTokens(user, agent);
    return {
      user,
      tokens,
    };
  }

  private async generateTokens(user: User, agent: string): Promise<Tokens> {
    const accessToken = this.jwtService.sign({
      id: user.id,
      email: user.email,
      roles: user.roles,
    });
    const refreshToken = await this.getRefreshToken(user.id, agent);
    return {
      accessToken,
      refreshToken,
    };
  }

  private async getRefreshToken(userId: string, agent: string): Promise<Token> {
    const _token = await this.prismaService.token.findFirst({
      where: {
        userId,
        userAgent: agent,
      },
    });
    const token = _token?.token ?? '';
    return this.prismaService.token.upsert({
      where: {
        token,
      },
      update: {
        token: v4(),
        exp: add(new Date(), { months: 1 }),
      },
      create: {
        token: v4(),
        exp: add(new Date(), { months: 1 }),
        userId,
        userAgent: agent,
      },
    });
  }

  deleteRefreshToken(token: string) {
    return this.prismaService.token.delete({ where: { token } });
  }

  async providerAuth(email: string, agent: string, provider: Provider): Promise<UserWithTokens> {
    const isUserExists = await this.userService.findOne(email);
    if (isUserExists) {
      const user = await this.userService.create({ email, provider }).catch((err) => {
        this.logger.error(err);
        throw err;
      });
      const tokens = await this.generateTokens(user, agent);
      return {
        user,
        tokens,
      };
    }
    const user = await this.userService.create({ email, provider }).catch((err) => {
      this.logger.error(err);
      throw err;
    });
    if (!user) {
      throw new HttpException('Cannot create user with this e-mail through the Google Auth!', HttpStatus.BAD_REQUEST);
    }
    const tokens = await this.generateTokens(user, agent);
    return {
      user,
      tokens,
    };
  }
}
