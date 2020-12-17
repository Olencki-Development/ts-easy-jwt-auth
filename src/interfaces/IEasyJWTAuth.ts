import {
  EasyJWTAuthOptions,
  RegisterReturnValue,
  LoginReturnValue,
  RefreshReturnValue,
  ForgotPasswordReturnValue,
  ForgotPasswordUpdateReturnValue,
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

  forgotPassword(username: Username): Promise<ForgotPasswordReturnValue>
  forgotPasswordUpdate(
    username: Username,
    newPassword: Password,
    passwordResetToken: JsonWebToken
  ): Promise<ForgotPasswordUpdateReturnValue>

  refresh(refreshToken: JsonWebToken): Promise<RefreshReturnValue>

  onRequestUserForUsername(cb: GetUserForUsernameCallback): void
}
