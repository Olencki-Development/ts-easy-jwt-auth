import {
  EasyJWTAuthOptions,
  RegisterReturnValue,
  LoginReturnValue,
  Password,
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
  protected getUserForUsername: GetUserForUsernameCallback
  protected tokens: Record<JsonWebToken, JsonWebToken>
  constructor(options: EasyJWTAuthOptions)
  register(
    username: Username,
    password: Password,
    role?: Role
  ): Promise<RegisterReturnValue>
  login(username: Username, password: Password): Promise<LoginReturnValue>
  refresh(refreshToken: JsonWebToken): Promise<LoginReturnValue>
  logout(accessToken: JsonWebToken): void
  validate(
    accessToken: JsonWebToken,
    acceptedRoles?: Roles
  ): Promise<AuthReturnValue>
  onRequestUserForUsername(cb: GetUserForUsernameCallback): void
  protected _getAccessToken(username: Username, role: Role): string
  protected _getRefreshToken(username: Username, role: Role): string
}
