import UnauthorizedError from './errors/UnauthorizedError'
import ForbiddenError from './errors/ForbiddenError'
import InvalidRoleError from './errors/InvalidRoleError'
import DuplicateUserError from './errors/DuplicateUserError'

export { EasyJWTAuth } from './EasyJWTAuth'
export const errors = {
  UnauthorizedError,
  ForbiddenError,
  InvalidRoleError,
  DuplicateUserError
}
