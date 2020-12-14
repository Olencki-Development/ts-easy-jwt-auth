"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EasyJWTAuth = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const UnauthorizedError_1 = __importDefault(require("./errors/UnauthorizedError"));
const ForbiddenError_1 = __importDefault(require("./errors/ForbiddenError"));
const InvalidRoleError_1 = __importDefault(require("./errors/InvalidRoleError"));
const defaultGetUserForUsername = () => {
    throw new Error(`IEasyJWTAuth::onRequestUserForUsername has not been set.`);
};
class EasyJWTAuth {
    constructor(options) {
        this._getUserForUsername = defaultGetUserForUsername;
        this._tokens = {}; /* refreshToken -> accessToken */
        this.options = options;
    }
    async register(username, password, role) {
        const saltRounds = this.options.saltRounds || 10;
        const hash = await bcrypt_1.default.hash(password, saltRounds);
        const _role = role || this.options.roles.default;
        if (!this.options.roles.available.includes(_role)) {
            throw new InvalidRoleError_1.default();
        }
        const refreshToken = this._getRefreshToken(username, _role);
        const accessToken = this._getAccessToken(username, _role);
        this._tokens[refreshToken] = accessToken;
        return {
            userInfo: {
                hash,
                role: _role
            },
            tokens: {
                refresh: refreshToken,
                access: accessToken
            }
        };
    }
    async login(username, password) {
        const user = await this._getUserForUsername(username);
        const matches = await bcrypt_1.default.compare(password, user.hash);
        if (!matches) {
            throw new UnauthorizedError_1.default();
        }
        const refreshToken = this._getRefreshToken(username, user.role);
        const accessToken = this._getAccessToken(username, user.role);
        this._tokens[refreshToken] = accessToken;
        return {
            tokens: {
                refresh: refreshToken,
                access: accessToken
            }
        };
    }
    async refresh(refreshToken) {
        const existingAccessToken = this._tokens[refreshToken];
        if (!existingAccessToken) {
            throw new ForbiddenError_1.default();
        }
        const payload = jsonwebtoken_1.default.verify(refreshToken, this.options.secrets.refreshToken);
        const accessToken = this._getAccessToken(payload.username, payload.role);
        this._tokens[refreshToken] = accessToken;
        return {
            tokens: {
                refresh: refreshToken,
                access: accessToken
            }
        };
    }
    logout(accessToken) {
        const item = Object.entries(this._tokens).find(([_, access]) => {
            return access === accessToken;
        });
        if (!item) {
            throw new ForbiddenError_1.default();
        }
        const refreshToken = item[0];
        delete this._tokens[refreshToken];
    }
    async validate(accessToken, acceptedRoles = []) {
        const item = Object.entries(this._tokens).find(([_, access]) => {
            return access === accessToken;
        });
        if (!item) {
            throw new ForbiddenError_1.default();
        }
        const payload = jsonwebtoken_1.default.verify(accessToken, this.options.secrets.accessToken);
        let hasRole = false;
        if (acceptedRoles.length > 0) {
            acceptedRoles.forEach((role) => {
                if (role === payload.role) {
                    hasRole = true;
                }
            });
        }
        else {
            hasRole = true;
        }
        if (!hasRole) {
            throw new ForbiddenError_1.default();
        }
        return this._getUserForUsername(payload.username);
    }
    onRequestUserForUsername(cb) {
        this._getUserForUsername = cb;
    }
    _getAccessToken(username, role) {
        const expiresIn = this.options.accessTokenExpiresInMinutes || 90;
        const accessToken = jsonwebtoken_1.default.sign({
            username,
            role
        }, this.options.secrets.accessToken, {
            expiresIn: `${expiresIn}m`
        });
        return accessToken;
    }
    _getRefreshToken(username, role) {
        const refreshToken = jsonwebtoken_1.default.sign({
            username,
            role
        }, this.options.secrets.refreshToken);
        return refreshToken;
    }
}
exports.EasyJWTAuth = EasyJWTAuth;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRWFzeUpXVEF1dGguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvRWFzeUpXVEF1dGgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsb0RBQTJCO0FBQzNCLGdFQUE4QjtBQUM5QixtRkFBMEQ7QUFDMUQsNkVBQW9EO0FBQ3BELGlGQUF3RDtBQWdCeEQsTUFBTSx5QkFBeUIsR0FBK0IsR0FBRyxFQUFFO0lBQ2pFLE1BQU0sSUFBSSxLQUFLLENBQUMsMERBQTBELENBQUMsQ0FBQTtBQUM3RSxDQUFDLENBQUE7QUFFRCxNQUFhLFdBQVc7SUFTdEIsWUFBWSxPQUEyQjtRQU43Qix3QkFBbUIsR0FBK0IseUJBQXlCLENBQUE7UUFDM0UsWUFBTyxHQUdiLEVBQUUsQ0FBQSxDQUFDLGlDQUFpQztRQUd0QyxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQTtJQUN4QixDQUFDO0lBRUQsS0FBSyxDQUFDLFFBQVEsQ0FDWixRQUFrQixFQUNsQixRQUFrQixFQUNsQixJQUFXO1FBRVgsTUFBTSxVQUFVLEdBQUcsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLElBQUksRUFBRSxDQUFBO1FBQ2hELE1BQU0sSUFBSSxHQUFHLE1BQU0sZ0JBQU0sQ0FBQyxJQUFJLENBQUMsUUFBUSxFQUFFLFVBQVUsQ0FBQyxDQUFBO1FBRXBELE1BQU0sS0FBSyxHQUFHLElBQUksSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUE7UUFDaEQsSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDakQsTUFBTSxJQUFJLDBCQUFnQixFQUFFLENBQUE7U0FDN0I7UUFFRCxNQUFNLFlBQVksR0FBRyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsUUFBUSxFQUFFLEtBQUssQ0FBQyxDQUFBO1FBQzNELE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxlQUFlLENBQUMsUUFBUSxFQUFFLEtBQUssQ0FBQyxDQUFBO1FBRXpELElBQUksQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUcsV0FBVyxDQUFBO1FBRXhDLE9BQU87WUFDTCxRQUFRLEVBQUU7Z0JBQ1IsSUFBSTtnQkFDSixJQUFJLEVBQUUsS0FBSzthQUNaO1lBQ0QsTUFBTSxFQUFFO2dCQUNOLE9BQU8sRUFBRSxZQUFZO2dCQUNyQixNQUFNLEVBQUUsV0FBVzthQUNwQjtTQUNGLENBQUE7SUFDSCxDQUFDO0lBRUQsS0FBSyxDQUFDLEtBQUssQ0FDVCxRQUFrQixFQUNsQixRQUFrQjtRQUVsQixNQUFNLElBQUksR0FBRyxNQUFNLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxRQUFRLENBQUMsQ0FBQTtRQUVyRCxNQUFNLE9BQU8sR0FBRyxNQUFNLGdCQUFNLENBQUMsT0FBTyxDQUFDLFFBQVEsRUFBRSxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUE7UUFDekQsSUFBSSxDQUFDLE9BQU8sRUFBRTtZQUNaLE1BQU0sSUFBSSwyQkFBaUIsRUFBRSxDQUFBO1NBQzlCO1FBRUQsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDLGdCQUFnQixDQUFDLFFBQVEsRUFBRSxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUE7UUFDL0QsTUFBTSxXQUFXLEdBQUcsSUFBSSxDQUFDLGVBQWUsQ0FBQyxRQUFRLEVBQUUsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFBO1FBRTdELElBQUksQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUcsV0FBVyxDQUFBO1FBRXhDLE9BQU87WUFDTCxNQUFNLEVBQUU7Z0JBQ04sT0FBTyxFQUFFLFlBQVk7Z0JBQ3JCLE1BQU0sRUFBRSxXQUFXO2FBQ3BCO1NBQ0YsQ0FBQTtJQUNILENBQUM7SUFFRCxLQUFLLENBQUMsT0FBTyxDQUFDLFlBQTBCO1FBQ3RDLE1BQU0sbUJBQW1CLEdBQUcsSUFBSSxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQTtRQUN0RCxJQUFJLENBQUMsbUJBQW1CLEVBQUU7WUFDeEIsTUFBTSxJQUFJLHdCQUFjLEVBQUUsQ0FBQTtTQUMzQjtRQUVELE1BQU0sT0FBTyxHQUF3QixzQkFBRyxDQUFDLE1BQU0sQ0FDN0MsWUFBWSxFQUNaLElBQUksQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FDWCxDQUFBO1FBRXhCLE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxlQUFlLENBQUMsT0FBTyxDQUFDLFFBQVEsRUFBRSxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUE7UUFFeEUsSUFBSSxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRyxXQUFXLENBQUE7UUFFeEMsT0FBTztZQUNMLE1BQU0sRUFBRTtnQkFDTixPQUFPLEVBQUUsWUFBWTtnQkFDckIsTUFBTSxFQUFFLFdBQVc7YUFDcEI7U0FDRixDQUFBO0lBQ0gsQ0FBQztJQUVELE1BQU0sQ0FBQyxXQUF5QjtRQUM5QixNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxNQUFNLENBQUMsRUFBRSxFQUFFO1lBQzdELE9BQU8sTUFBTSxLQUFLLFdBQVcsQ0FBQTtRQUMvQixDQUFDLENBQUMsQ0FBQTtRQUVGLElBQUksQ0FBQyxJQUFJLEVBQUU7WUFDVCxNQUFNLElBQUksd0JBQWMsRUFBRSxDQUFBO1NBQzNCO1FBRUQsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFBO1FBRTVCLE9BQU8sSUFBSSxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQTtJQUNuQyxDQUFDO0lBRUQsS0FBSyxDQUFDLFFBQVEsQ0FDWixXQUF5QixFQUN6QixnQkFBdUIsRUFBRTtRQUV6QixNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxNQUFNLENBQUMsRUFBRSxFQUFFO1lBQzdELE9BQU8sTUFBTSxLQUFLLFdBQVcsQ0FBQTtRQUMvQixDQUFDLENBQUMsQ0FBQTtRQUVGLElBQUksQ0FBQyxJQUFJLEVBQUU7WUFDVCxNQUFNLElBQUksd0JBQWMsRUFBRSxDQUFBO1NBQzNCO1FBRUQsTUFBTSxPQUFPLEdBQXdCLHNCQUFHLENBQUMsTUFBTSxDQUM3QyxXQUFXLEVBQ1gsSUFBSSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsV0FBVyxDQUNWLENBQUE7UUFFeEIsSUFBSSxPQUFPLEdBQUcsS0FBSyxDQUFBO1FBQ25CLElBQUksYUFBYSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUU7WUFDNUIsYUFBYSxDQUFDLE9BQU8sQ0FBQyxDQUFDLElBQUksRUFBRSxFQUFFO2dCQUM3QixJQUFJLElBQUksS0FBSyxPQUFPLENBQUMsSUFBSSxFQUFFO29CQUN6QixPQUFPLEdBQUcsSUFBSSxDQUFBO2lCQUNmO1lBQ0gsQ0FBQyxDQUFDLENBQUE7U0FDSDthQUFNO1lBQ0wsT0FBTyxHQUFHLElBQUksQ0FBQTtTQUNmO1FBRUQsSUFBSSxDQUFDLE9BQU8sRUFBRTtZQUNaLE1BQU0sSUFBSSx3QkFBYyxFQUFFLENBQUE7U0FDM0I7UUFFRCxPQUFPLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUE7SUFDbkQsQ0FBQztJQUVELHdCQUF3QixDQUFDLEVBQThCO1FBQ3JELElBQUksQ0FBQyxtQkFBbUIsR0FBRyxFQUFFLENBQUE7SUFDL0IsQ0FBQztJQUVTLGVBQWUsQ0FBQyxRQUFrQixFQUFFLElBQVU7UUFDdEQsTUFBTSxTQUFTLEdBQUcsSUFBSSxDQUFDLE9BQU8sQ0FBQywyQkFBMkIsSUFBSSxFQUFFLENBQUE7UUFDaEUsTUFBTSxXQUFXLEdBQUcsc0JBQUcsQ0FBQyxJQUFJLENBQzFCO1lBQ0UsUUFBUTtZQUNSLElBQUk7U0FDTCxFQUNELElBQUksQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLFdBQVcsRUFDaEM7WUFDRSxTQUFTLEVBQUUsR0FBRyxTQUFTLEdBQUc7U0FDM0IsQ0FDRixDQUFBO1FBRUQsT0FBTyxXQUFXLENBQUE7SUFDcEIsQ0FBQztJQUVTLGdCQUFnQixDQUFDLFFBQWtCLEVBQUUsSUFBVTtRQUN2RCxNQUFNLFlBQVksR0FBRyxzQkFBRyxDQUFDLElBQUksQ0FDM0I7WUFDRSxRQUFRO1lBQ1IsSUFBSTtTQUNMLEVBQ0QsSUFBSSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUNsQyxDQUFBO1FBRUQsT0FBTyxZQUFZLENBQUE7SUFDckIsQ0FBQztDQUNGO0FBMUtELGtDQTBLQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBiY3J5cHQgZnJvbSAnYmNyeXB0J1xuaW1wb3J0IGp3dCBmcm9tICdqc29ud2VidG9rZW4nXG5pbXBvcnQgVW5hdXRob3JpemVkRXJyb3IgZnJvbSAnLi9lcnJvcnMvVW5hdXRob3JpemVkRXJyb3InXG5pbXBvcnQgRm9yYmlkZGVuRXJyb3IgZnJvbSAnLi9lcnJvcnMvRm9yYmlkZGVuRXJyb3InXG5pbXBvcnQgSW52YWxpZFJvbGVFcnJvciBmcm9tICcuL2Vycm9ycy9JbnZhbGlkUm9sZUVycm9yJ1xuaW1wb3J0IHtcbiAgRWFzeUpXVEF1dGhPcHRpb25zLFxuICBSZWdpc3RlclJldHVyblZhbHVlLFxuICBMb2dpblJldHVyblZhbHVlLFxuICBQYXNzd29yZCxcbiAgVXNlcm5hbWUsXG4gIFJvbGUsXG4gIFJvbGVzLFxuICBKc29uV2ViVG9rZW4sXG4gIEF1dGhSZXR1cm5WYWx1ZSxcbiAgR2V0VXNlckZvclVzZXJuYW1lQ2FsbGJhY2ssXG4gIEpzb25XZWJUb2tlblBheWxvYWRcbn0gZnJvbSAnLi90eXBlcy9FYXN5SldUQXV0aCdcbmltcG9ydCB7IElFYXN5SldUQXV0aCB9IGZyb20gJy4vaW50ZXJmYWNlcy9JRWFzeUpXVEF1dGgnXG5cbmNvbnN0IGRlZmF1bHRHZXRVc2VyRm9yVXNlcm5hbWU6IEdldFVzZXJGb3JVc2VybmFtZUNhbGxiYWNrID0gKCkgPT4ge1xuICB0aHJvdyBuZXcgRXJyb3IoYElFYXN5SldUQXV0aDo6b25SZXF1ZXN0VXNlckZvclVzZXJuYW1lIGhhcyBub3QgYmVlbiBzZXQuYClcbn1cblxuZXhwb3J0IGNsYXNzIEVhc3lKV1RBdXRoIGltcGxlbWVudHMgSUVhc3lKV1RBdXRoIHtcbiAgb3B0aW9uczogRWFzeUpXVEF1dGhPcHRpb25zXG5cbiAgcHJvdGVjdGVkIF9nZXRVc2VyRm9yVXNlcm5hbWU6IEdldFVzZXJGb3JVc2VybmFtZUNhbGxiYWNrID0gZGVmYXVsdEdldFVzZXJGb3JVc2VybmFtZVxuICBwcm90ZWN0ZWQgX3Rva2VuczogUmVjb3JkPFxuICAgIEpzb25XZWJUb2tlbixcbiAgICBKc29uV2ViVG9rZW5cbiAgPiA9IHt9IC8qIHJlZnJlc2hUb2tlbiAtPiBhY2Nlc3NUb2tlbiAqL1xuXG4gIGNvbnN0cnVjdG9yKG9wdGlvbnM6IEVhc3lKV1RBdXRoT3B0aW9ucykge1xuICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnNcbiAgfVxuXG4gIGFzeW5jIHJlZ2lzdGVyKFxuICAgIHVzZXJuYW1lOiBVc2VybmFtZSxcbiAgICBwYXNzd29yZDogUGFzc3dvcmQsXG4gICAgcm9sZT86IFJvbGVcbiAgKTogUHJvbWlzZTxSZWdpc3RlclJldHVyblZhbHVlPiB7XG4gICAgY29uc3Qgc2FsdFJvdW5kcyA9IHRoaXMub3B0aW9ucy5zYWx0Um91bmRzIHx8IDEwXG4gICAgY29uc3QgaGFzaCA9IGF3YWl0IGJjcnlwdC5oYXNoKHBhc3N3b3JkLCBzYWx0Um91bmRzKVxuXG4gICAgY29uc3QgX3JvbGUgPSByb2xlIHx8IHRoaXMub3B0aW9ucy5yb2xlcy5kZWZhdWx0XG4gICAgaWYgKCF0aGlzLm9wdGlvbnMucm9sZXMuYXZhaWxhYmxlLmluY2x1ZGVzKF9yb2xlKSkge1xuICAgICAgdGhyb3cgbmV3IEludmFsaWRSb2xlRXJyb3IoKVxuICAgIH1cblxuICAgIGNvbnN0IHJlZnJlc2hUb2tlbiA9IHRoaXMuX2dldFJlZnJlc2hUb2tlbih1c2VybmFtZSwgX3JvbGUpXG4gICAgY29uc3QgYWNjZXNzVG9rZW4gPSB0aGlzLl9nZXRBY2Nlc3NUb2tlbih1c2VybmFtZSwgX3JvbGUpXG5cbiAgICB0aGlzLl90b2tlbnNbcmVmcmVzaFRva2VuXSA9IGFjY2Vzc1Rva2VuXG5cbiAgICByZXR1cm4ge1xuICAgICAgdXNlckluZm86IHtcbiAgICAgICAgaGFzaCxcbiAgICAgICAgcm9sZTogX3JvbGVcbiAgICAgIH0sXG4gICAgICB0b2tlbnM6IHtcbiAgICAgICAgcmVmcmVzaDogcmVmcmVzaFRva2VuLFxuICAgICAgICBhY2Nlc3M6IGFjY2Vzc1Rva2VuXG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgbG9naW4oXG4gICAgdXNlcm5hbWU6IFVzZXJuYW1lLFxuICAgIHBhc3N3b3JkOiBQYXNzd29yZFxuICApOiBQcm9taXNlPExvZ2luUmV0dXJuVmFsdWU+IHtcbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy5fZ2V0VXNlckZvclVzZXJuYW1lKHVzZXJuYW1lKVxuXG4gICAgY29uc3QgbWF0Y2hlcyA9IGF3YWl0IGJjcnlwdC5jb21wYXJlKHBhc3N3b3JkLCB1c2VyLmhhc2gpXG4gICAgaWYgKCFtYXRjaGVzKSB7XG4gICAgICB0aHJvdyBuZXcgVW5hdXRob3JpemVkRXJyb3IoKVxuICAgIH1cblxuICAgIGNvbnN0IHJlZnJlc2hUb2tlbiA9IHRoaXMuX2dldFJlZnJlc2hUb2tlbih1c2VybmFtZSwgdXNlci5yb2xlKVxuICAgIGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5fZ2V0QWNjZXNzVG9rZW4odXNlcm5hbWUsIHVzZXIucm9sZSlcblxuICAgIHRoaXMuX3Rva2Vuc1tyZWZyZXNoVG9rZW5dID0gYWNjZXNzVG9rZW5cblxuICAgIHJldHVybiB7XG4gICAgICB0b2tlbnM6IHtcbiAgICAgICAgcmVmcmVzaDogcmVmcmVzaFRva2VuLFxuICAgICAgICBhY2Nlc3M6IGFjY2Vzc1Rva2VuXG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgcmVmcmVzaChyZWZyZXNoVG9rZW46IEpzb25XZWJUb2tlbik6IFByb21pc2U8TG9naW5SZXR1cm5WYWx1ZT4ge1xuICAgIGNvbnN0IGV4aXN0aW5nQWNjZXNzVG9rZW4gPSB0aGlzLl90b2tlbnNbcmVmcmVzaFRva2VuXVxuICAgIGlmICghZXhpc3RpbmdBY2Nlc3NUb2tlbikge1xuICAgICAgdGhyb3cgbmV3IEZvcmJpZGRlbkVycm9yKClcbiAgICB9XG5cbiAgICBjb25zdCBwYXlsb2FkOiBKc29uV2ViVG9rZW5QYXlsb2FkID0gand0LnZlcmlmeShcbiAgICAgIHJlZnJlc2hUb2tlbixcbiAgICAgIHRoaXMub3B0aW9ucy5zZWNyZXRzLnJlZnJlc2hUb2tlblxuICAgICkgYXMgSnNvbldlYlRva2VuUGF5bG9hZFxuXG4gICAgY29uc3QgYWNjZXNzVG9rZW4gPSB0aGlzLl9nZXRBY2Nlc3NUb2tlbihwYXlsb2FkLnVzZXJuYW1lLCBwYXlsb2FkLnJvbGUpXG5cbiAgICB0aGlzLl90b2tlbnNbcmVmcmVzaFRva2VuXSA9IGFjY2Vzc1Rva2VuXG5cbiAgICByZXR1cm4ge1xuICAgICAgdG9rZW5zOiB7XG4gICAgICAgIHJlZnJlc2g6IHJlZnJlc2hUb2tlbixcbiAgICAgICAgYWNjZXNzOiBhY2Nlc3NUb2tlblxuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGxvZ291dChhY2Nlc3NUb2tlbjogSnNvbldlYlRva2VuKTogdm9pZCB7XG4gICAgY29uc3QgaXRlbSA9IE9iamVjdC5lbnRyaWVzKHRoaXMuX3Rva2VucykuZmluZCgoW18sIGFjY2Vzc10pID0+IHtcbiAgICAgIHJldHVybiBhY2Nlc3MgPT09IGFjY2Vzc1Rva2VuXG4gICAgfSlcblxuICAgIGlmICghaXRlbSkge1xuICAgICAgdGhyb3cgbmV3IEZvcmJpZGRlbkVycm9yKClcbiAgICB9XG5cbiAgICBjb25zdCByZWZyZXNoVG9rZW4gPSBpdGVtWzBdXG5cbiAgICBkZWxldGUgdGhpcy5fdG9rZW5zW3JlZnJlc2hUb2tlbl1cbiAgfVxuXG4gIGFzeW5jIHZhbGlkYXRlKFxuICAgIGFjY2Vzc1Rva2VuOiBKc29uV2ViVG9rZW4sXG4gICAgYWNjZXB0ZWRSb2xlczogUm9sZXMgPSBbXVxuICApOiBQcm9taXNlPEF1dGhSZXR1cm5WYWx1ZT4ge1xuICAgIGNvbnN0IGl0ZW0gPSBPYmplY3QuZW50cmllcyh0aGlzLl90b2tlbnMpLmZpbmQoKFtfLCBhY2Nlc3NdKSA9PiB7XG4gICAgICByZXR1cm4gYWNjZXNzID09PSBhY2Nlc3NUb2tlblxuICAgIH0pXG5cbiAgICBpZiAoIWl0ZW0pIHtcbiAgICAgIHRocm93IG5ldyBGb3JiaWRkZW5FcnJvcigpXG4gICAgfVxuXG4gICAgY29uc3QgcGF5bG9hZDogSnNvbldlYlRva2VuUGF5bG9hZCA9IGp3dC52ZXJpZnkoXG4gICAgICBhY2Nlc3NUb2tlbixcbiAgICAgIHRoaXMub3B0aW9ucy5zZWNyZXRzLmFjY2Vzc1Rva2VuXG4gICAgKSBhcyBKc29uV2ViVG9rZW5QYXlsb2FkXG5cbiAgICBsZXQgaGFzUm9sZSA9IGZhbHNlXG4gICAgaWYgKGFjY2VwdGVkUm9sZXMubGVuZ3RoID4gMCkge1xuICAgICAgYWNjZXB0ZWRSb2xlcy5mb3JFYWNoKChyb2xlKSA9PiB7XG4gICAgICAgIGlmIChyb2xlID09PSBwYXlsb2FkLnJvbGUpIHtcbiAgICAgICAgICBoYXNSb2xlID0gdHJ1ZVxuICAgICAgICB9XG4gICAgICB9KVxuICAgIH0gZWxzZSB7XG4gICAgICBoYXNSb2xlID0gdHJ1ZVxuICAgIH1cblxuICAgIGlmICghaGFzUm9sZSkge1xuICAgICAgdGhyb3cgbmV3IEZvcmJpZGRlbkVycm9yKClcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5fZ2V0VXNlckZvclVzZXJuYW1lKHBheWxvYWQudXNlcm5hbWUpXG4gIH1cblxuICBvblJlcXVlc3RVc2VyRm9yVXNlcm5hbWUoY2I6IEdldFVzZXJGb3JVc2VybmFtZUNhbGxiYWNrKTogdm9pZCB7XG4gICAgdGhpcy5fZ2V0VXNlckZvclVzZXJuYW1lID0gY2JcbiAgfVxuXG4gIHByb3RlY3RlZCBfZ2V0QWNjZXNzVG9rZW4odXNlcm5hbWU6IFVzZXJuYW1lLCByb2xlOiBSb2xlKTogc3RyaW5nIHtcbiAgICBjb25zdCBleHBpcmVzSW4gPSB0aGlzLm9wdGlvbnMuYWNjZXNzVG9rZW5FeHBpcmVzSW5NaW51dGVzIHx8IDkwXG4gICAgY29uc3QgYWNjZXNzVG9rZW4gPSBqd3Quc2lnbihcbiAgICAgIHtcbiAgICAgICAgdXNlcm5hbWUsXG4gICAgICAgIHJvbGVcbiAgICAgIH0sXG4gICAgICB0aGlzLm9wdGlvbnMuc2VjcmV0cy5hY2Nlc3NUb2tlbixcbiAgICAgIHtcbiAgICAgICAgZXhwaXJlc0luOiBgJHtleHBpcmVzSW59bWBcbiAgICAgIH1cbiAgICApXG5cbiAgICByZXR1cm4gYWNjZXNzVG9rZW5cbiAgfVxuXG4gIHByb3RlY3RlZCBfZ2V0UmVmcmVzaFRva2VuKHVzZXJuYW1lOiBVc2VybmFtZSwgcm9sZTogUm9sZSk6IHN0cmluZyB7XG4gICAgY29uc3QgcmVmcmVzaFRva2VuID0gand0LnNpZ24oXG4gICAgICB7XG4gICAgICAgIHVzZXJuYW1lLFxuICAgICAgICByb2xlXG4gICAgICB9LFxuICAgICAgdGhpcy5vcHRpb25zLnNlY3JldHMucmVmcmVzaFRva2VuXG4gICAgKVxuXG4gICAgcmV0dXJuIHJlZnJlc2hUb2tlblxuICB9XG59XG4iXX0=