import { Token } from '@prisma/client';
import { UserResponse } from '@user/responses';

export interface Tokens {
  accessToken: string;
  refreshToken: Token;
}

export interface UserWithTokens {
  user: UserResponse;
  tokens: Tokens;
}

export interface JwtPayload {
  id: string;
  email: string;
  roles: string[];
}
