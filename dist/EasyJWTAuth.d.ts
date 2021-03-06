import {
  EasyJWTAuthOptions,
  RegisterReturnValue,
  LoginReturnValue,
  RefreshReturnValue,
  ForgotPasswordReturnValue,
  ForgotPasswordUpdateReturnValue,
  Password,
  PasswordHash,
  Username,
  Role,
  Roles,
  JsonWebToken,
  AuthReturnValue,
  GetUserForUsernameCallback
} from './types/EasyJWTAuth'
import { IEasyJWTAuth } from './interfaces/IEasyJWTAuth'
export declare class EasyJWTAuth implements IEasyJWTAuth {
  options: EasyJWTAuthOptions
  protected _getUserForUsername: GetUserForUsernameCallback
  protected _tokens: Record<JsonWebToken, JsonWebToken>
  protected _passwordResetTokens: Record<Username, JsonWebToken>
  constructor(options: EasyJWTAuthOptions)
  register(
    username: Username,
    password: Password,
    role?: Role
  ): Promise<RegisterReturnValue>
  login(username: Username, password: Password): Promise<LoginReturnValue>
  refresh(refreshToken: JsonWebToken): Promise<RefreshReturnValue>
  logout(accessToken: JsonWebToken): void
  forgotPassword(username: Username): Promise<ForgotPasswordReturnValue>
  forgotPasswordUpdate(
    username: Username,
    newPassword: Password,
    passwordResetToken: JsonWebToken
  ): Promise<ForgotPasswordUpdateReturnValue>
  validate(
    accessToken: JsonWebToken,
    acceptedRoles?: Roles
  ): Promise<AuthReturnValue>
  onRequestUserForUsername(cb: GetUserForUsernameCallback): void
  protected _getAccessToken(username: Username, role: Role): string
  protected _getRefreshToken(username: Username, role: Role): string
  protected _getPasswordResetToken(): string
  protected _getHash(password: Password): Promise<PasswordHash>
}
