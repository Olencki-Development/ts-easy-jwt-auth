import { IEasyJWTAuthError } from '../interfaces/IEasyJWTAuthError'
export default class ForbiddenError extends Error implements IEasyJWTAuthError {
  statusCode: number
  constructor()
}
