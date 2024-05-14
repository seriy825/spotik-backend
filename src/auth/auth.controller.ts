import {
  BadRequestException,
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { SignInDTO, SignUpDTO } from './dto';
import { AuthService } from './auth.service';
import { ApiBadRequestResponse, ApiCreatedResponse, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { UserWithTokens } from './types';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { Cookie, Public, UserAgent } from '@common/decorators';
import { UserResponse } from '@user/responses';
import { GoogleGuard } from './guards/google.guard';
import { FRONT_END_GOOGLE_AUTH_REDIRECT_PATH } from '@common/constants';
import { HttpService } from '@nestjs/axios';
import { map, mergeMap } from 'rxjs';
import { handleTimeoutAndErrors } from '@common/helpers';
import { Provider } from '@prisma/client';
import { ACCESS_TOKEN, REFRESH_TOKEN } from 'src/utils/constants';

@ApiTags('Auth')
@Public()
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
  ) {}

  @UseInterceptors(ClassSerializerInterceptor)
  @Post('sign-up')
  @ApiCreatedResponse({
    description: 'Success sign-up action!',
    type: 'application/json',
  })
  @ApiBadRequestResponse({ description: 'Cannot register user!' })
  async signUp(@Body() signUpDTO: SignUpDTO) {
    const user = await this.authService.signUp(signUpDTO);
    if (!user) {
      throw new BadRequestException(`Cannot register user ${signUpDTO.email}`);
    }
    return new UserResponse(user);
  }

  @UseInterceptors(ClassSerializerInterceptor)
  @Post('sign-in')
  @ApiOkResponse({ description: 'Success login!', type: 'application/json' })
  @ApiBadRequestResponse({ description: 'Bad credentials!' })
  async signIn(@Body() signInDTO: SignInDTO, @Res() res: Response, @UserAgent() agent: string) {
    const signInResponse = await this.authService.signIn(signInDTO, agent);
    if (!signInResponse) {
      throw new BadRequestException(`Cannot sign-in user ${signInDTO.email}`);
    }
    this.setRefreshTokenToCookie(signInResponse, res);
  }

  @Get('refresh-tokens')
  @ApiOkResponse({ description: 'Tokens refreshed!', type: 'application/json' })
  async refreshTokens(@Cookie(REFRESH_TOKEN) refreshToken: string, @Res() res: Response, @UserAgent() agent: string) {
    if (!refreshToken) {
      throw new UnauthorizedException();
    }
    const refreshTokensResult = await this.authService.refreshTokens(refreshToken, agent);
    if (!refreshTokensResult) {
      throw new UnauthorizedException();
    }
    this.setRefreshTokenToCookie(refreshTokensResult, res);
  }

  @Get('logout')
  async logout(@Cookie(REFRESH_TOKEN) refreshToken: string, @Res() res: Response) {
    if (!refreshToken) {
      res.sendStatus(HttpStatus.OK);
      return;
    }
    await this.authService.deleteRefreshToken(refreshToken);
    res.cookie(REFRESH_TOKEN, '', { httpOnly: true, secure: true, expires: new Date() });
    res.sendStatus(HttpStatus.OK);
  }

  @UseInterceptors(ClassSerializerInterceptor)
  private setRefreshTokenToCookie(userWithTokens: UserWithTokens, res: Response) {
    if (!userWithTokens) {
      throw new UnauthorizedException();
    }
    res.cookie(REFRESH_TOKEN, userWithTokens.tokens.refreshToken.token, {
      httpOnly: true,
      sameSite: 'lax',
      expires: new Date(userWithTokens.tokens.refreshToken.exp),
      secure: this.configService.get('NODE_ENV', 'development') === 'production',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.cookie(ACCESS_TOKEN, userWithTokens.tokens.accessToken, {
      httpOnly: true,
      sameSite: 'lax',
      expires: new Date(new Date().getTime() + 3 * 24 * 60 * 60),
      secure: this.configService.get('NODE_ENV', 'development') === 'production',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res
      .status(HttpStatus.OK)
      .json({ accessToken: userWithTokens.tokens.accessToken, user: new UserResponse(userWithTokens.user) });
  }

  @UseGuards(GoogleGuard)
  @Get('google')
  googleAuth() {}

  @UseGuards(GoogleGuard)
  @Get('google/callback')
  googleAuthCallback(@Req() req: Request, @Res() res: Response) {
    const token = req.user['accessToken'];
    return res.redirect(
      `${this.configService.get('FRONT_END_URL')}${FRONT_END_GOOGLE_AUTH_REDIRECT_PATH}?token=${token}`,
    );
  }

  //Mock for front-end endpoint
  @Get('success')
  success(@Query('token') token: string, @UserAgent() agent: string, @Res() res: Response) {
    const _token = token.replace('}', '');
    return this.httpService.get(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${_token}`).pipe(
      mergeMap(({ data: { email } }) => this.authService.providerAuth(email, agent, Provider.GOOGLE)),
      map((data) => this.setRefreshTokenToCookie(data, res)),
      handleTimeoutAndErrors(),
    );
  }
}
