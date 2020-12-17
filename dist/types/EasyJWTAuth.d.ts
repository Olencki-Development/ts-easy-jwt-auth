export declare type EasyJWTAuthOptions = {
  roles: {
    available: Roles
    default: Role
  }
  saltRounds?: number
  secrets: {
    accessToken: string
    refreshToken: string
    passwordResetToken: string
  }
  accessTokenExpiresInMinutes?: number
  passwordResetTokenExpiresInMinutes?: number
}
export declare type Username = string
export declare type Password = string
export declare type Role = string
export declare type Roles = Role[]
export declare type PasswordHash = string
export declare type JsonWebToken = string
export declare type JsonWebTokenPayload = {
  username: Username
  role: Role
}
export declare type UserType = {
  [key: string]: any
  hash: PasswordHash
  role: Role
}
export declare type GetUserForUsernameCallback = (
  username: Username
) => Promise<UserType>
export declare type RegisterReturnValue = RefreshReturnValue & {
  userInfo: {
    hash: PasswordHash
    role: Role
  }
}
export declare type LoginReturnValue = RefreshReturnValue & {
  user: UserType
}
export declare type RefreshReturnValue = {
  tokens: {
    refresh: JsonWebToken
    access: JsonWebToken
  }
}
export declare type ForgotPasswordReturnValue = {
  user: UserType
  tokens: {
    passwordReset: JsonWebToken
  }
}
export declare type ForgotPasswordUpdateReturnValue = {
  user: UserType
}
export declare type AuthReturnValue = LoginReturnValue
