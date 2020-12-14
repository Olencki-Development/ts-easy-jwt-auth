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
} from '../types/EasyJWTAuth'

export interface IEasyJWTAuthClass {
  new (options: EasyJWTAuthOptions): IEasyJWTAuth
}

export interface IEasyJWTAuth {
  options: EasyJWTAuthOptions

  register(
    username: Username,
    password: Password,
    role?: Role
  ): Promise<RegisterReturnValue>

  login(username: Username, password: Password): Promise<LoginReturnValue>

  validate(
    accessToken: JsonWebToken,
    acceptedRoles: Roles
  ): Promise<AuthReturnValue>

  logout(accessToken: JsonWebToken): void

  refresh(refreshToken: JsonWebToken): Promise<LoginReturnValue>

  onRequestUserForUsername(cb: GetUserForUsernameCallback): void
}
