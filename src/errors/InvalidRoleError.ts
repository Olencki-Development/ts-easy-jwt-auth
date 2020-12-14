export default class InvalidRoleError extends Error {
  constructor() {
    super('Invalid role specified.')

    this.name = this.constructor.name
  }
}
