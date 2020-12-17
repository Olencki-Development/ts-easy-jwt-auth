import { IEasyJWTAuthError } from '../interfaces/IEasyJWTAuthError'

export default class ForbiddenError extends Error implements IEasyJWTAuthError {
  statusCode: number

  constructor() {
    super('Forbidden.')

    this.name = this.constructor.name
    this.statusCode = 403
  }
}
