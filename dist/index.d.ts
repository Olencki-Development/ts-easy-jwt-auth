import UnauthorizedError from './errors/UnauthorizedError'
import ForbiddenError from './errors/ForbiddenError'
import InvalidRoleError from './errors/InvalidRoleError'
export { EasyJWTAuth } from './EasyJWTAuth'
export declare const errors: {
  UnauthorizedError: typeof UnauthorizedError
  ForbiddenError: typeof ForbiddenError
  InvalidRoleError: typeof InvalidRoleError
}
