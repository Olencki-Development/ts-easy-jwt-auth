import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import UnauthorizedError from './errors/UnauthorizedError'
import ForbiddenError from './errors/ForbiddenError'
import DuplicateUserError from './errors/DuplicateUserError'
import InvalidRoleError from './errors/InvalidRoleError'
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
  GetUserForUsernameCallback,
  JsonWebTokenPayload
} from './types/EasyJWTAuth'
import { IEasyJWTAuth } from './interfaces/IEasyJWTAuth'

const defaultGetUserForUsername: GetUserForUsernameCallback = () => {
  throw new Error(`IEasyJWTAuth::onRequestUserForUsername has not been set.`)
}

export class EasyJWTAuth implements IEasyJWTAuth {
  options: EasyJWTAuthOptions

  protected _getUserForUsername: GetUserForUsernameCallback = defaultGetUserForUsername
  protected _tokens: Record<
    JsonWebToken,
    JsonWebToken
  > = {} /* refreshToken -> accessToken */
  protected _passwordResetTokens: Record<Username, JsonWebToken> = {}

  constructor(options: EasyJWTAuthOptions) {
    this.options = options
  }

  async register(
    username: Username,
    password: Password,
    role?: Role
  ): Promise<RegisterReturnValue> {
    let existingUser
    try {
      existingUser = await this._getUserForUsername(username)
    } catch (_) {
      // no-opt
    }
    if (existingUser) {
      throw new DuplicateUserError()
    }

    const hash = await this._getHash(password)

    const _role = role || this.options.roles.default
    if (!this.options.roles.available.includes(_role)) {
      throw new InvalidRoleError()
    }

    const refreshToken = this._getRefreshToken(username, _role)
    const accessToken = this._getAccessToken(username, _role)

    this._tokens[refreshToken] = accessToken

    return {
      userInfo: {
        hash,
        role: _role
      },
      tokens: {
        refresh: refreshToken,
        access: accessToken
      }
    }
  }

  async login(
    username: Username,
    password: Password
  ): Promise<LoginReturnValue> {
    const user = await this._getUserForUsername(username)

    const matches = await bcrypt.compare(password, user.hash)
    if (!matches) {
      throw new UnauthorizedError()
    }

    const refreshToken = this._getRefreshToken(username, user.role)
    const accessToken = this._getAccessToken(username, user.role)

    this._tokens[refreshToken] = accessToken

    return {
      tokens: {
        refresh: refreshToken,
        access: accessToken
      },
      user
    }
  }

  async refresh(refreshToken: JsonWebToken): Promise<RefreshReturnValue> {
    const existingAccessToken = this._tokens[refreshToken]
    if (!existingAccessToken) {
      throw new ForbiddenError()
    }

    const payload: JsonWebTokenPayload = jwt.verify(
      refreshToken,
      this.options.secrets.refreshToken
    ) as JsonWebTokenPayload

    const accessToken = this._getAccessToken(payload.username, payload.role)

    this._tokens[refreshToken] = accessToken

    return {
      tokens: {
        refresh: refreshToken,
        access: accessToken
      }
    }
  }

  logout(accessToken: JsonWebToken): void {
    const item = Object.entries(this._tokens).find(([_, access]) => {
      return access === accessToken
    })

    if (!item) {
      throw new ForbiddenError()
    }

    const refreshToken = item[0]

    delete this._tokens[refreshToken]
  }

  async forgotPassword(username: Username): Promise<ForgotPasswordReturnValue> {
    const user = await this._getUserForUsername(username)
    const resetToken = this._getPasswordResetToken()
    this._passwordResetTokens[username] = resetToken

    return {
      user,
      tokens: {
        passwordReset: resetToken
      }
    }
  }

  async forgotPasswordUpdate(
    username: Username,
    newPassword: Password,
    passwordResetToken: JsonWebToken
  ): Promise<ForgotPasswordUpdateReturnValue> {
    const token = this._passwordResetTokens[username]
    if (!token) {
      throw new ForbiddenError()
    }

    if (token !== passwordResetToken) {
      throw new UnauthorizedError()
    }

    jwt.verify(token, this.options.secrets.passwordResetToken)

    const user = await this._getUserForUsername(username)
    user.hash = await this._getHash(newPassword)

    delete this._passwordResetTokens[username]

    return {
      user
    }
  }

  async validate(
    accessToken: JsonWebToken,
    acceptedRoles: Roles = []
  ): Promise<AuthReturnValue> {
    let _accessToken = accessToken
    if (_accessToken && _accessToken.includes(' ')) {
      const splitToken = _accessToken.split(' ')
      _accessToken = splitToken[1]
    }

    const item = Object.entries(this._tokens).find(([_, access]) => {
      return access === _accessToken
    })

    if (!item) {
      throw new ForbiddenError()
    }

    const payload: JsonWebTokenPayload = jwt.verify(
      _accessToken,
      this.options.secrets.accessToken
    ) as JsonWebTokenPayload

    let hasRole = false
    if (acceptedRoles.length > 0) {
      acceptedRoles.forEach((role) => {
        if (role === payload.role) {
          hasRole = true
        }
      })
    } else {
      hasRole = true
    }

    if (!hasRole) {
      throw new ForbiddenError()
    }

    const user = await this._getUserForUsername(payload.username)
    return {
      user,
      tokens: {
        access: item[1],
        refresh: item[0]
      }
    }
  }

  onRequestUserForUsername(cb: GetUserForUsernameCallback): void {
    this._getUserForUsername = cb
  }

  protected _getAccessToken(username: Username, role: Role): string {
    const expiresIn = this.options.accessTokenExpiresInMinutes || 90
    const accessToken = jwt.sign(
      {
        username,
        role
      },
      this.options.secrets.accessToken,
      {
        expiresIn: expiresIn * 60 // convert minutes to seconds
      }
    )

    return accessToken
  }

  protected _getRefreshToken(username: Username, role: Role): string {
    const refreshToken = jwt.sign(
      {
        username,
        role
      },
      this.options.secrets.refreshToken
    )

    return refreshToken
  }

  protected _getPasswordResetToken(): string {
    const expiresIn = this.options.passwordResetTokenExpiresInMinutes || 10
    const passwordResetToken = jwt.sign(
      {},
      this.options.secrets.passwordResetToken,
      {
        expiresIn: expiresIn * 60 // convert minutes to seconds
      }
    )

    return passwordResetToken
  }

  protected async _getHash(password: Password): Promise<PasswordHash> {
    const saltRounds = this.options.saltRounds || 10
    const hash = await bcrypt.hash(password, saltRounds)
    return hash
  }
}
