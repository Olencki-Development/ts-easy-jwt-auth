"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.errors = exports.EasyJWTAuth = void 0;
const UnauthorizedError_1 = __importDefault(require("./errors/UnauthorizedError"));
const ForbiddenError_1 = __importDefault(require("./errors/ForbiddenError"));
const InvalidRoleError_1 = __importDefault(require("./errors/InvalidRoleError"));
const DuplicateUserError_1 = __importDefault(require("./errors/DuplicateUserError"));
var EasyJWTAuth_1 = require("./EasyJWTAuth");
Object.defineProperty(exports, "EasyJWTAuth", { enumerable: true, get: function () { return EasyJWTAuth_1.EasyJWTAuth; } });
exports.errors = {
    UnauthorizedError: UnauthorizedError_1.default,
    ForbiddenError: ForbiddenError_1.default,
    InvalidRoleError: InvalidRoleError_1.default,
    DuplicateUserError: DuplicateUserError_1.default
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsbUZBQTBEO0FBQzFELDZFQUFvRDtBQUNwRCxpRkFBd0Q7QUFDeEQscUZBQTREO0FBRTVELDZDQUEyQztBQUFsQywwR0FBQSxXQUFXLE9BQUE7QUFDUCxRQUFBLE1BQU0sR0FBRztJQUNwQixpQkFBaUIsRUFBakIsMkJBQWlCO0lBQ2pCLGNBQWMsRUFBZCx3QkFBYztJQUNkLGdCQUFnQixFQUFoQiwwQkFBZ0I7SUFDaEIsa0JBQWtCLEVBQWxCLDRCQUFrQjtDQUNuQixDQUFBIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IFVuYXV0aG9yaXplZEVycm9yIGZyb20gJy4vZXJyb3JzL1VuYXV0aG9yaXplZEVycm9yJ1xuaW1wb3J0IEZvcmJpZGRlbkVycm9yIGZyb20gJy4vZXJyb3JzL0ZvcmJpZGRlbkVycm9yJ1xuaW1wb3J0IEludmFsaWRSb2xlRXJyb3IgZnJvbSAnLi9lcnJvcnMvSW52YWxpZFJvbGVFcnJvcidcbmltcG9ydCBEdXBsaWNhdGVVc2VyRXJyb3IgZnJvbSAnLi9lcnJvcnMvRHVwbGljYXRlVXNlckVycm9yJ1xuXG5leHBvcnQgeyBFYXN5SldUQXV0aCB9IGZyb20gJy4vRWFzeUpXVEF1dGgnXG5leHBvcnQgY29uc3QgZXJyb3JzID0ge1xuICBVbmF1dGhvcml6ZWRFcnJvcixcbiAgRm9yYmlkZGVuRXJyb3IsXG4gIEludmFsaWRSb2xlRXJyb3IsXG4gIER1cGxpY2F0ZVVzZXJFcnJvclxufVxuIl19