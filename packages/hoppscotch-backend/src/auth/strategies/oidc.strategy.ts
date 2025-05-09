import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import * as E from 'fp-ts/Either';
import * as O from 'fp-ts/Option';
import { Profile, Strategy, VerifyCallback } from 'passport-openidconnect';
import { UserService } from 'src/user/user.service';
import { AuthService } from '../auth.service';
import { StatelessStateStore } from '../stateless-state-store';

@Injectable()
export class OidcStrategy extends PassportStrategy(Strategy) {
  constructor(
    private usersService: UserService,
    private authService: AuthService,
    private configService: ConfigService,
  ) {
    super({
      issuer: configService.get<string>('INFRA.OIDC_ISSUER'),
      authorizationURL: configService.get<string>('INFRA.OIDC_AUTH_URL'),
      tokenURL: configService.get<string>('INFRA.OIDC_TOKEN_URL'),
      userInfoURL: configService.get<string>('INFRA.OIDC_USERINFO_URL'),
      clientID: configService.get<string>('INFRA.OIDC_CLIENT_ID'),
      clientSecret: configService.get<string>('INFRA.OIDC_CLIENT_SECRET'),
      callbackURL: configService.get<string>('INFRA.OIDC_CALLBACK_URL'),
      scope: configService.get<string>('INFRA.OIDC_SCOPE')
        ? configService.get<string>('INFRA.OIDC_SCOPE').split(',')
        : ['openid'],
      store: new StatelessStateStore(
        configService.get<string>('INFRA.SESSION_SECRET'),
        undefined,
        (configService.get<string>('INFRA.SESSION_COOKIE_NAME') ||
          '__oauth_nonce') + '_oidc',
        configService.get<string>('INFRA.ALLOW_SECURE_COOKIES') === 'true',
      ),
    });
  }

  async validate(
    issuer: string,
    profile: Profile,
    context: object,
    idToken: string | object,
    accessToken: string,
    refreshToken: string,
    done: VerifyCallback, // eslint-disable-line @typescript-eslint/no-unused-vars
  ) {
    const user = await this.usersService.findUserByEmail(
      profile.emails[0].value,
    );
    profile.provider = 'oidc';

    if (O.isNone(user)) {
      const createdUser = await this.usersService.createUserSSO(
        accessToken,
        refreshToken,
        profile,
      );
      return createdUser;
    }

    /**
     * * displayName and photoURL maybe null if user logged-in via magic-link before SSO
     */
    if (!user.value.displayName || !user.value.photoURL) {
      const updatedUser = await this.usersService.updateUserDetails(
        user.value,
        profile,
      );
      if (E.isLeft(updatedUser)) {
        throw new UnauthorizedException(updatedUser.left);
      }
    }

    /**
     * * Check to see if entry for Google is present in the Account table for user
     * * If user was created with another provider findUserByEmail may return true
     */
    const providerAccountExists =
      await this.authService.checkIfProviderAccountExists(user.value, profile);

    if (O.isNone(providerAccountExists))
      await this.usersService.createProviderAccount(
        user.value,
        accessToken,
        refreshToken,
        profile,
      );

    return user.value;
  }
}
