import Vapor
import HTTP
import Auth
import Turnstile
import TurnstileCrypto
import TurnstileWeb
import VaporJWT

final class AuthController {
    
    func register(request: Request) throws -> ResponseRepresentable {
        // Get our credentials
        guard let username = request.data["username"]?.string, let password = request.data["password"]?.string else {
            throw Abort.custom(status: Status.badRequest, message: "Missing username or password")
        }
        let credentials = UsernamePassword(username: username, password: password)
        
        // Try to register the user
        do {
            try _ = User.register(credentials: credentials)
            try request.auth.login(credentials)
            
            return try JSON(node: Node.successNode(data: ["user": request.user().publicNode(),
                                                          "token": request.user().makeTokenNode()]))
        } catch let e as TurnstileError {
            throw Abort.custom(status: Status.badRequest, message: e.description)
        }
    }
    
    func login(request: Request) throws -> ResponseRepresentable {
        // Get our credentials
        guard let username = request.data["username"]?.string, let password = request.data["password"]?.string else {
            throw Abort.custom(status: Status.badRequest, message: "Missing username or password")
        }
        let credentials = UsernamePassword(username: username, password: password)
        
        do {
            try request.auth.login(credentials)
            return try JSON(node: Node.successNode(data: ["user": request.user().publicNode(),
                                                          "token": request.user().makeTokenNode()]))
        } catch _ {
            throw Abort.custom(status: Status.badRequest, message: "Invalid email or password")
        }
    }
    
    func logout(request: Request) throws -> ResponseRepresentable {
        // Invalidate the current access token
        var user = try request.user()
        user.accessToken = nil
        user.refreshToken = nil;
        try user.save()
        
        // Clear the session
        request.subject.logout()
        return try JSON(node: Node.successNode(data: []))
    }
    
    func refresh(request: Request) throws -> ResponseRepresentable {
        var user: User?
        
        guard let refreshToken = request.data["refresh_token"]?.string else {
            throw Abort.custom(status: Status.badRequest, message: "Missing refresh_token")
        }
        
        let refreshJWT = try JWT(token: refreshToken)
        
        do {
            user = try User.query().filter("refresh_token", refreshToken).first()
        } catch {
            throw Abort.notFound
        }
        
        if var user = user {
            
            if try refreshJWT.verifySignatureWith(HS256(key: Authentication.RefreshTokenSigningKey)) {
                if refreshJWT.verifyClaims([ExpirationTimeClaim()]) {
                    
                    try user.generateAccessToken()
                    try user.generateRefreshToken()
                    try user.save()
                    
                    return try JSON(node: Node.successNode(data: user.makeTokenNode()))
                    
                } else {
                    throw Abort.custom(status: .unauthorized, message: "Refresh token expired.")
                }
            } else {
                throw Abort.custom(status: .unauthorized, message: "Refresh token signature is invalid.")
            }

        } else {
            throw Abort.custom(status: .unauthorized, message: "Invalid refresh token.")
        }
    }
}
