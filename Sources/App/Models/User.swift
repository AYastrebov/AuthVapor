import Vapor
import Fluent
import HTTP
import Auth
import Foundation
import Turnstile
import TurnstileWeb
import TurnstileCrypto
import VaporJWT
import Hash

struct Authentication {
    static let AccessTokenSigningKey: Bytes = Array("ACCESS_TOKEN_SECRET".utf8)
    static let AccesTokenValidationLength = Date() + (60 * 15) // 15 Minutes later
    static let RefreshTokenSigningKey: Bytes = Array("REFRESH_TOKEN_SECRET".utf8)
    static let RefreshTokenValidationLength = Date() + (60 * 60 * 24 * 30) // 30 Days Later
}

final class User: BaseModel, Model {
    
    var username: String!
    var password: String!
    var accessToken: String?
    var refreshToken: String?
    
    init(credentials: UsernamePassword) {
        self.username = credentials.username
        self.password = BCrypt.hash(password: credentials.password)
        super.init()
    }
    
    init(credentials: Auth.AccessToken) {
        self.accessToken = credentials.string
        super.init()
    }
    
    override init(node: Node, in context: Context) throws {
        username = try node.extract("username")
        password = try node.extract("password")
        accessToken = try node.extract("access_token")
        refreshToken = try node.extract("refresh_token")
        try super.init(node: node, in: context)
    }
    
    override func makeNode(context: Context) throws -> Node {
        return try Node(node: [
            "id": id,
            "created_on": createdOn,
            "username": username,
            "password": password,
            "refresh_token": refreshToken,
            "access_token": accessToken,
            ])
    }
}

// MARK: Authentication
extension User: Auth.User {
    @discardableResult
    static func authenticate(credentials: Credentials) throws -> Auth.User {
        var user: User?
        
        switch credentials {
            case let credentials as UsernamePassword:
                let fetchedUser = try User.query().filter("username", credentials.username).first()
                if let password = fetchedUser?.password, password != "",
                    (try? BCrypt.verify(password: credentials.password, matchesHash: password)) == true {
                    user = fetchedUser
                }
            
            case let credentials as Identifier:
                user = try User.find(credentials.id)
            
            case let credentials as Auth.AccessToken:
                user = try User.query().filter("access_token", credentials.string).first()
            
            default:
                throw UnsupportedCredentialsError()
        }
        
        if var user = user {
            // Check if we have an accessToken first, if not, lets create a new one
            if let accessToken = user.accessToken {
                // Check if our authentication token has expired, if so, lets generate a new one as this is a fresh login
                let receivedJWT = try JWT(token: accessToken)
                
                // Validate it's time stamp
                if !receivedJWT.verifyClaims([ExpirationTimeClaim()]) {
                    try user.generateToken()
                }
            } else {
                // We don't have a valid access token
                try user.generateToken()
            }
            
            try user.save()
            
            return user
        } else {
            throw IncorrectCredentialsError()
        }
    }
    
    @discardableResult
    static func register(credentials: Credentials) throws -> Auth.User {
        var newUser: User
        
        switch credentials {
            case let credentials as UsernamePassword:
                newUser = User(credentials: credentials)
            
            default:
                throw UnsupportedCredentialsError()
        }
        
        if try User.query().filter("username", newUser.username).first() == nil {
            try newUser.generateToken()
            try newUser.save()
            return newUser
        } else {
            throw AccountTakenError()
        }
    }
}

// MARK: Token Generation
extension User {
    func generateToken() throws {
        // Generate our Token
        let jwt = try JWT(payload: Node(ExpirationTimeClaim(Authentication.AccesTokenValidationLength)),
                          signer: HS256(key: Authentication.AccessTokenSigningKey))
        self.accessToken = try jwt.createToken()
    }
    
    func validateToken() throws -> Bool {
        guard let token = self.accessToken else { return false }
        // Validate our current access token
        let receivedJWT = try JWT(token: token)
        if try receivedJWT.verifySignatureWith(HS256(key: Authentication.AccessTokenSigningKey)) {
            // If we need a new token, lets generate one
            if !receivedJWT.verifyClaims([ExpirationTimeClaim()]) {
                try self.generateToken()
                return true
            }
        }
        return false
    }
}

// MARK: Preparations
extension User: Preparation {
    static func prepare(_ database: Database) throws {
        try database.create("users") { user in
            prepare(model: user)
            user.string("username")
            user.string("password")
            user.string("refresh_token", optional: true)
            user.string("access_token", optional: true)
        }
    }
    
    static func revert(_ database: Database) throws {
        try database.delete("users")
    }
}

// MARK: Merge
extension User {
    func merge(updates: User) {
        super.merge(updates: updates)
        username = updates.username
        password = updates.password
        accessToken = updates.accessToken
        refreshToken = updates.refreshToken
    }
}
